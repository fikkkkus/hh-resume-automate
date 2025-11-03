package com.github.s3rgeym.hh_resume_automate.api

import android.content.SharedPreferences
import android.net.Uri
import android.util.Log
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

sealed class ApiException(val json: Map<String, Any?>, message: String) : Exception(message) {

    companion object {
        // Вспомогательный метод для проверки, является ли JSON-ответ ошибкой превышения лимита
        // Этот метод вызывается ТОЛЬКО если HTTP-ответ НЕУСПЕШНЫЙ (т.е. response.isSuccessful == false)
        fun isLimitExceeded(json: Map<String, Any?>): Boolean {
            val errors = json["errors"] as? List<*> ?: return false
            return errors.any {
                (it as? Map<*, *>)?.get("value") == "limit_exceeded"
            }
        }
    }
}

class BadRequestException(json: Map<String, Any?>) : ApiException(json, "Bad Request")
class ForbiddenException(json: Map<String, Any?>) : ApiException(json, "Forbidden")
class ResourceNotFoundException(json: Map<String, Any?>) : ApiException(json, "Not Found")
class TooManyRequestsException(json: Map<String, Any?>) : ApiException(json, "Too Many Requests")
class LimitExceededException(json: Map<String, Any?>) : ApiException(json, "Limit Exceeded")
class ClientErrorException(json: Map<String, Any?>) : ApiException(json, "Client Error")
class ServerErrorException(json: Map<String, Any?>) : ApiException(json, "Server Error")

class ApiDelayInterceptor(private val apiDelay: Long) : Interceptor {
    private val lastRequestTime = AtomicLong(0)
    @Throws(IOException::class)
    override fun intercept(chain: Interceptor.Chain): Response {
        val lastTime = lastRequestTime.get()
        val waitTime = lastTime + apiDelay - System.currentTimeMillis()
        if (waitTime > 0) {
            System.err.println("wait $waitTime")
            Thread.sleep(waitTime)
        }
        lastRequestTime.set(System.currentTimeMillis())
        return chain.proceed(chain.request())
    }
}

class ApiClient(
    public var accessToken: String? = null,
    public var refreshToken: String? = null,
    public var accessExpiresAt: Long = 0,
    protected val apiDelay: Long = 300L,
    protected val apiUrl: String = ApiConstants.API_URL,
    protected val oauthUrl: String = ApiConstants.OAUTH_URL,
    protected val clientId: String = ApiConstants.CLIENT_ID,
    protected val clientSecret: String = ApiConstants.CLIENT_SECRET,
    protected val sharedPrefs: SharedPreferences? = null,
) {
    protected val client = OkHttpClient.Builder()
        .followRedirects(false)
        .addInterceptor(ApiDelayInterceptor(apiDelay))
        .build()

    init {
        sharedPrefs?.let { loadFromPrefs(it) }
    }

    val isAuthenticated: Boolean
        get() = !accessToken.isNullOrEmpty()

    val isAccessExpired: Boolean
        get() = System.currentTimeMillis() >= accessExpiresAt

    suspend fun api(
        method: String,
        endpoint: String,
        params: Map<String, Any?>? = null
    ): Map<String, Any?> = apiRequest(method, apiUrl, endpoint, params)

    suspend fun apiFromFullUrl(
        fullUrl: String
    ): Map<String, Any?> {
        return try {
            apiFromFullUrlGo(fullUrl)
        } catch (e: ForbiddenException) {
            if (isAccessExpired && refreshToken != null) {
                refreshAccessToken()
                apiFromFullUrlGo(fullUrl)
            } else {
                throw e
            }
        }
    }

    suspend fun apiFromFullUrlGo(fullUrl: String): Map<String, Any?> {
        val TAG = "ApiClient"
        val uri = android.net.Uri.parse(fullUrl)

        // Собираем ВСЕ параметры, включая повторяющиеся ключи
        val queryParams = mutableMapOf<String, MutableList<String>>()
        uri.queryParameterNames.forEach { key ->
            val values = uri.getQueryParameters(key)
            if (!values.isNullOrEmpty()) {
                queryParams.getOrPut(key) { mutableListOf() }.addAll(values.filter { it.isNotEmpty() })
            }
        }

        // ✅ Добавляем дефолты
        queryParams.getOrPut("page") { mutableListOf("0") }
        queryParams.getOrPut("per_page") { mutableListOf("100") }

        // Формируем финальный query string вручную
        val queryString = queryParams.flatMap { (key, values) ->
            values.map { value ->
                // 👇 Ключевая правка — кодируем, но превращаем %20 обратно в "+"
                val encoded = URLEncoder.encode(value, "UTF-8")
                    .replace("%2B", "+")     // если в тексте был плюс
                    .replace("%20", "+")     // hh.ru ожидает пробел как "+"
                "$key=$encoded"
            }
        }.joinToString("&")

        val requestUrl = "https://api.hh.ru/vacancies?$queryString"

        // --- Собираем запрос ---
        val request = Request.Builder()
            .url(requestUrl)
            .headers(defaultHeaders())
            .apply {
                accessToken?.let {
                    addHeader("Authorization", "Bearer $it")
                }
            }
            .get()
            .build()

        val start = System.currentTimeMillis()
        val response = client.newCall(request).execute()
        val duration = System.currentTimeMillis() - start

        // --- ЛОГИРУЕМ ЗАПРОС ---
        Log.d(TAG, "========================================")
        Log.d(TAG, "📤 REQUEST: ${request.method} ${request.url}")

        Log.d(TAG, "--- Headers ---")
        request.headers.forEach { (name, value) ->
            Log.d(TAG, "$name: $value")
        }

        request.body?.let { body ->
            val buffer = okio.Buffer()
            body.writeTo(buffer)
            val reqBody = buffer.readUtf8()
            Log.d(TAG, "--- Body (${reqBody.length} chars) ---")
            Log.d(TAG, reqBody.take(5000) + if (reqBody.length > 5000) "… [trimmed]" else "")
        }

        // --- cURL для Postman ---
        val curl = buildString {
            append("curl -X ${request.method} '${request.url}'")
            request.headers.forEach { (name, value) ->
                append(" -H \"$name: $value\"")
            }
            request.body?.let { body ->
                val buffer = okio.Buffer()
                body.writeTo(buffer)
                val reqBody = buffer.readUtf8()
                append(" --data '${reqBody.replace("'", "\\'")}'")
            }
        }
        Log.d(TAG, "🐚 cURL:\n$curl")

        // --- ЛОГИРУЕМ ОТВЕТ ---
        Log.d(TAG, "========================================")
        Log.d(TAG, "📥 RESPONSE (${duration} ms): ${response.code}")
        response.headers.forEach { (name, value) ->
            Log.d(TAG, "$name: $value")
        }

        val bodyStr = response.body?.string()?.trim().orEmpty()
        Log.d(TAG, "--- Body (${bodyStr.length} chars) ---")
        Log.d(TAG, bodyStr.take(8000) + if (bodyStr.length > 8000) "… [trimmed]" else "")
        Log.d(TAG, "========================================")

        // --- Проверки и возврат ---
        if (!response.isSuccessful) {
            throw BadRequestException(mapOf("error" to bodyStr))
        }

        if (bodyStr.startsWith("<!DOCTYPE")) {
            throw IOException("HTML received instead of JSON (Bad URL or not API domain)")
        }

        return JSONObject(bodyStr).toMap()
    }

    fun getAuthorizeUrl(redirectUri: String = "", state: String = "", scope: String = ""): String {
        val params = mapOf(
            "client_id" to clientId,
            "client_secret" to clientSecret,
            "redirect_uri" to redirectUri,
            "response_type" to "code",
            "scope" to scope,
            "state" to state
        ).filterValues { it.isNotEmpty() }
        return buildUrl(oauthUrl, "/authorize", params)
    }

    suspend fun authenticate(code: String): ApiClient {
        val params = mapOf(
            "client_id" to clientId,
            "client_secret" to clientSecret,
            "grant_type" to "authorization_code",
            "code" to code,
        )
        val token = request("POST", oauthUrl, "/token", params)
        handleToken(token)
        return this
    }

    suspend fun refreshAccessToken(): ApiClient {
        val params = mapOf(
            "client_id" to clientId,
            "client_secret" to clientSecret,
            "grant_type" to "refresh_token",
            "refresh_token" to (refreshToken ?: throw IllegalStateException("No refresh token"))
        )
        val token = request("POST", oauthUrl, "/token", params)
        handleToken(token)
        return this
    }

    protected suspend fun apiRequest(
        method: String,
        baseUrl: String,
        endpoint: String,
        params: Map<String, Any?>? = null,
    ): Map<String, Any?> {
        return try {
            request(method, baseUrl, endpoint, params, true)
        } catch (e: ForbiddenException) {
            if (isAccessExpired && refreshToken != null) {
                refreshAccessToken()
                request(method, baseUrl, endpoint, params, true)
            } else {
                throw e
            }
        }
    }

    protected suspend fun request(
        method: String,
        baseUrl: String,
        endpoint: String,
        params: Map<String, Any?>? = null,
        includeAuthHeader: Boolean = false,
    ): Map<String, Any?> {
        require(method in listOf("GET", "POST", "PUT", "DELETE")) { "Invalid HTTP method: $method" }
        val hasBody = method in listOf("POST", "PUT")
        val url = buildUrl(baseUrl, endpoint, if (hasBody) null else params?.mapValues { it.value?.toString() ?: "" })
        val requestBuilder = Request.Builder().url(url).headers(defaultHeaders())
        if (includeAuthHeader) {
            accessToken?.let {
                requestBuilder.addHeader("Authorization", "Bearer $it")
            }
        }
        if (hasBody) {
            val builder = FormBody.Builder()
            params?.forEach { (key, value) ->
                builder.add(key, value?.toString() ?: "")
            }
            val requestBody = builder.build()
            requestBuilder.method(method, requestBody)
        } else if (method != "GET") {
            requestBuilder.method(method, null)
        }

        val response = client.newCall(requestBuilder.build()).execute()
        System.err.println("[${response.code}] ${response.request.method} ${response.request.url}")
        val bodyStr = response.body?.string()?.trim()
        val json = if (!bodyStr.isNullOrEmpty()) JSONObject(bodyStr).toMap() else emptyMap()

        // Теперь проверка на неуспешный ответ происходит перед анализом JSON
        if (!response.isSuccessful) {
            throwApiException(response, json)
        }
        return json.toMap()
    }

    protected fun buildUrl(baseUrl: String, endpoint: String, params: Map<String, Any?>? = null): String {
        val u = Uri.parse(baseUrl)
        val ub = Uri.Builder().scheme(u.scheme).authority(u.authority)
        ub.path(u.path?.removeSuffix("/") + "/" + endpoint.removePrefix("/"))
        params?.forEach { (k, v) ->
            ub.appendQueryParameter(k, v?.toString() ?: "")
        }
        return ub.build().toString()
    }

    protected fun generateRandomDeviceModel(): String {
        val charset = ('A'..'Z') + ('0'..'9')
        return (1..10)
            .map { charset.random(Random) }
            .joinToString("")
    }

    protected fun generateUserAgent(): String {
        val major = Random.nextInt(5, 7)
        val minor = Random.nextInt(100, 150)
        val patch = Random.nextInt(10000, 15000)
        val randomDeviceModel = generateRandomDeviceModel()
        val androidOsVersion = Random.nextInt(10, 15)
        val randomUuid = UUID.randomUUID().toString()

        // Оригинальный:
        // ru.hh.android/7.122.11395, Device: 23053RN02Y, Android OS: 13 (UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

        // Рандомный:
        // ru.hh.android/6.149.14615, Device: ZV6EK4FGOR, Android OS: 12 (UUID: a482b404-b4d8-4f6b-9ac0-48be9367a42a)
        return "ru.hh.android/$major.$minor.$patch, Device: $randomDeviceModel, Android OS: $androidOsVersion (UUID: $randomUuid)"
    }

    protected fun defaultHeaders(): Headers {
        val userAgent = generateUserAgent()
        System.err.println("Random User-Agent: $userAgent")
        return Headers.Builder().apply {
            add("Accept", "*/*")
            add("User-Agent", userAgent)
        }.build()
    }

    protected fun throwApiException(response: Response, json: Map<String, Any?>) {
        // Мы находимся в этом методе только потому, что response.isSuccessful == false.
        // Теперь проверка на LimitExceededException идет первой в цепочке,
        // так как это наиболее специфический случай ошибки, который может сопровождаться разными кодами.
        if (ApiException.isLimitExceeded(json)) {
            throw LimitExceededException(json.toMap())
        }

        // Если это не LimitExceeded по JSON, то проверяем по HTTP-коду.
        when (response.code) {
            400 -> throw BadRequestException(json.toMap())
            403 -> throw ForbiddenException(json.toMap())
            404 -> throw ResourceNotFoundException(json.toMap())
            429 -> throw TooManyRequestsException(json.toMap()) // Это останется для общих 429
            in 400 until 500 -> throw ClientErrorException(json.toMap())
            in 500..599 -> throw ServerErrorException(json.toMap())
            else -> throw IOException("Unexpected API response code: ${response.code}")
        }
    }

    protected fun handleToken(token: Map<String, Any?>) {
        System.err.println("token: $token")
        accessToken = token["access_token"] as? String
        refreshToken = token["refresh_token"] as? String
        accessExpiresAt = ((token["expires_in"] as? Number)?.toLong() ?: 0) * 1000 + System.currentTimeMillis()
        sharedPrefs?.let { saveToPrefs(it) }
    }

    fun saveToPrefs(sharedPrefs: SharedPreferences) {
        with(sharedPrefs.edit()) {
            putString("access_token", accessToken)
            putString("refresh_token", refreshToken)
            putLong("access_expires_at", accessExpiresAt)
            apply()
        }
    }

    fun loadFromPrefs(sharedPrefs: SharedPreferences) {
        accessToken = sharedPrefs.getString("access_token", null) ?: ""
        refreshToken = sharedPrefs.getString("refresh_token", null) ?: ""
        accessExpiresAt = sharedPrefs.getLong("access_expires_at", 0)
    }
}

fun JSONObject.toMap(): Map<String, Any?> {
    val map = mutableMapOf<String, Any?>()
    val keys = this.keys()
    while (keys.hasNext()) {
        val key = keys.next()
        val value = this[key]
        map[key] = when (value) {
            is JSONObject -> value.toMap()
            is org.json.JSONArray -> value.toList()
            else -> value
        }
    }
    return map
}

fun org.json.JSONArray.toList(): List<Any?> {
    return (0 until this.length()).map { index ->
        when (val value = this[index]) {
            is JSONObject -> value.toMap()
            is org.json.JSONArray -> value.toList()
            else -> value
        }
    }
}
