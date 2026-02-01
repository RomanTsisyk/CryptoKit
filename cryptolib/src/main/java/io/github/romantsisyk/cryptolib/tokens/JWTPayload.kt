package io.github.romantsisyk.cryptolib.tokens

import org.json.JSONObject
import java.util.Date

/**
 * Data class representing a JWT payload with standard claims and custom claims.
 * @param iss Issuer - identifies the principal that issued the JWT.
 * @param sub Subject - identifies the principal that is the subject of the JWT.
 * @param aud Audience - identifies the recipients that the JWT is intended for.
 * @param exp Expiration Time - identifies the expiration time after which the JWT must not be accepted.
 * @param iat Issued At - identifies the time at which the JWT was issued.
 * @param nbf Not Before - identifies the time before which the JWT must not be accepted.
 * @param jti JWT ID - provides a unique identifier for the JWT.
 * @param customClaims Additional custom claims.
 */
data class JWTPayload(
    val iss: String? = null,
    val sub: String? = null,
    val aud: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    val nbf: Long? = null,
    val jti: String? = null,
    val customClaims: Map<String, Any> = emptyMap()
) {
    /**
     * Converts the JWT payload to a JSON string.
     * @return JSON string representation of the payload.
     */
    fun toJson(): String {
        return JSONObject().apply {
            iss?.let { put("iss", it) }
            sub?.let { put("sub", it) }
            aud?.let { put("aud", it) }
            exp?.let { put("exp", it) }
            iat?.let { put("iat", it) }
            nbf?.let { put("nbf", it) }
            jti?.let { put("jti", it) }

            // Add custom claims
            customClaims.forEach { (key, value) ->
                put(key, value)
            }
        }.toString()
    }

    /**
     * Checks if the token is expired based on the current time.
     * @param currentTimeMillis Current time in milliseconds (defaults to system time).
     * @return true if the token is expired, false otherwise.
     */
    fun isExpired(currentTimeMillis: Long = System.currentTimeMillis()): Boolean {
        return exp?.let { expirationTime ->
            val currentTimeSeconds = currentTimeMillis / 1000
            currentTimeSeconds >= expirationTime
        } ?: false
    }

    /**
     * Checks if the token is valid based on the 'nbf' (not before) claim.
     * @param currentTimeMillis Current time in milliseconds (defaults to system time).
     * @return true if the token is not yet valid, false otherwise.
     */
    fun isNotYetValid(currentTimeMillis: Long = System.currentTimeMillis()): Boolean {
        return nbf?.let { notBeforeTime ->
            val currentTimeSeconds = currentTimeMillis / 1000
            currentTimeSeconds < notBeforeTime
        } ?: false
    }

    companion object {
        /**
         * Creates a JWTPayload from a JSON string.
         * @param json The JSON string to parse.
         * @return A JWTPayload instance.
         */
        fun fromJson(json: String): JWTPayload {
            val jsonObject = JSONObject(json)

            // Extract standard claims
            val iss = jsonObject.optString("iss").takeIf { it.isNotEmpty() }
            val sub = jsonObject.optString("sub").takeIf { it.isNotEmpty() }
            val aud = jsonObject.optString("aud").takeIf { it.isNotEmpty() }
            val exp = if (jsonObject.has("exp")) jsonObject.getLong("exp") else null
            val iat = if (jsonObject.has("iat")) jsonObject.getLong("iat") else null
            val nbf = if (jsonObject.has("nbf")) jsonObject.getLong("nbf") else null
            val jti = jsonObject.optString("jti").takeIf { it.isNotEmpty() }

            // Extract custom claims
            val standardClaims = setOf("iss", "sub", "aud", "exp", "iat", "nbf", "jti")
            val customClaims = mutableMapOf<String, Any>()

            jsonObject.keys().forEach { key ->
                if (key !in standardClaims) {
                    customClaims[key] = jsonObject.get(key)
                }
            }

            return JWTPayload(
                iss = iss,
                sub = sub,
                aud = aud,
                exp = exp,
                iat = iat,
                nbf = nbf,
                jti = jti,
                customClaims = customClaims
            )
        }
    }
}
