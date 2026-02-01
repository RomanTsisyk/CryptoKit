package io.github.romantsisyk.cryptolib.tokens

import org.json.JSONObject

/**
 * Data class representing a JWT header.
 * @param alg The algorithm used for signing the JWT.
 * @param typ The type of token, typically "JWT".
 */
data class JWTHeader(
    val alg: JWTAlgorithm,
    val typ: String = "JWT"
) {
    /**
     * Converts the JWT header to a JSON string.
     * @return JSON string representation of the header.
     */
    fun toJson(): String {
        return JSONObject().apply {
            put("alg", alg.algorithmName)
            put("typ", typ)
        }.toString()
    }

    companion object {
        /**
         * Creates a JWTHeader from a JSON string.
         * @param json The JSON string to parse.
         * @return A JWTHeader instance.
         * @throws IllegalArgumentException if the JSON is invalid or missing required fields.
         */
        fun fromJson(json: String): JWTHeader {
            val jsonObject = JSONObject(json)
            val algString = jsonObject.optString("alg")
            val typ = jsonObject.optString("typ", "JWT")

            if (algString.isEmpty()) {
                throw IllegalArgumentException("Missing 'alg' field in JWT header")
            }

            return JWTHeader(
                alg = JWTAlgorithm.fromString(algString),
                typ = typ
            )
        }
    }
}
