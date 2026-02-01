package io.github.romantsisyk.cryptolib.crypto.kdf

/**
 * Enum representing supported Key Derivation Function (KDF) algorithms.
 * These algorithms are used to derive cryptographic keys from passwords.
 */
enum class KDFAlgorithm(val algorithmName: String) {
    /**
     * PBKDF2 with HMAC-SHA256.
     * Provides a good balance between security and performance.
     */
    PBKDF2_SHA256("PBKDF2WithHmacSHA256"),

    /**
     * PBKDF2 with HMAC-SHA512.
     * Provides stronger security at the cost of slightly more computation.
     */
    PBKDF2_SHA512("PBKDF2WithHmacSHA512")
}
