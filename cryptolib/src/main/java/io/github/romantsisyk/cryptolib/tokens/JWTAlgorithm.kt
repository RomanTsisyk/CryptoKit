package io.github.romantsisyk.cryptolib.tokens

/**
 * Enum representing supported JWT algorithms.
 * Includes both HMAC (HS256, HS384, HS512) and RSA (RS256, RS384, RS512) algorithms.
 */
enum class JWTAlgorithm(val algorithmName: String, val javaAlgorithm: String) {
    /**
     * HMAC using SHA-256 hash algorithm.
     */
    HS256("HS256", "HmacSHA256"),

    /**
     * HMAC using SHA-384 hash algorithm.
     */
    HS384("HS384", "HmacSHA384"),

    /**
     * HMAC using SHA-512 hash algorithm.
     */
    HS512("HS512", "HmacSHA512"),

    /**
     * RSA signature using SHA-256 hash algorithm.
     */
    RS256("RS256", "SHA256withRSA"),

    /**
     * RSA signature using SHA-384 hash algorithm.
     */
    RS384("RS384", "SHA384withRSA"),

    /**
     * RSA signature using SHA-512 hash algorithm.
     */
    RS512("RS512", "SHA512withRSA");

    /**
     * Checks if this algorithm is an HMAC-based algorithm.
     */
    fun isHmac(): Boolean = this in setOf(HS256, HS384, HS512)

    /**
     * Checks if this algorithm is an RSA-based algorithm.
     */
    fun isRsa(): Boolean = this in setOf(RS256, RS384, RS512)

    companion object {
        /**
         * Gets the JWTAlgorithm from its string representation.
         * @param algorithmName The algorithm name (e.g., "HS256", "RS256").
         * @return The corresponding JWTAlgorithm.
         * @throws IllegalArgumentException if the algorithm is not supported.
         */
        fun fromString(algorithmName: String): JWTAlgorithm {
            return values().find { it.algorithmName == algorithmName }
                ?: throw IllegalArgumentException("Unsupported algorithm: $algorithmName")
        }
    }
}
