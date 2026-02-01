package io.github.romantsisyk.cryptolib.crypto.hashing

/**
 * Enumeration of supported hash algorithms.
 * Each algorithm specifies the standard name used by the Java security provider.
 *
 * @property algorithmName The standard name of the hash algorithm as recognized by MessageDigest and Mac.
 */
enum class HashAlgorithm(val algorithmName: String) {
    /**
     * SHA-256 algorithm (256-bit hash).
     * Part of the SHA-2 family, widely used for cryptographic purposes.
     */
    SHA256("SHA-256"),

    /**
     * SHA-384 algorithm (384-bit hash).
     * Part of the SHA-2 family, provides stronger security than SHA-256.
     */
    SHA384("SHA-384"),

    /**
     * SHA-512 algorithm (512-bit hash).
     * Part of the SHA-2 family, provides the strongest security in SHA-2.
     */
    SHA512("SHA-512"),

    /**
     * SHA3-256 algorithm (256-bit hash).
     * Part of the SHA-3 family (Keccak), latest NIST standard.
     */
    SHA3_256("SHA3-256"),

    /**
     * SHA3-512 algorithm (512-bit hash).
     * Part of the SHA-3 family (Keccak), provides the strongest security in SHA-3.
     */
    SHA3_512("SHA3-512"),

    /**
     * MD5 algorithm (128-bit hash).
     * NOTE: MD5 is cryptographically broken and should NOT be used for security purposes.
     * Included only for legacy compatibility and non-security use cases like checksums.
     */
    @Deprecated("MD5 is cryptographically weak and should not be used for security purposes")
    MD5("MD5");

    /**
     * Returns the HMAC algorithm name for this hash algorithm.
     * Used for generating HMAC (Hash-based Message Authentication Code).
     *
     * @return The HMAC algorithm name (e.g., "HmacSHA256" for SHA256).
     */
    fun toHmacAlgorithm(): String = "Hmac${algorithmName.replace("-", "")}"
}
