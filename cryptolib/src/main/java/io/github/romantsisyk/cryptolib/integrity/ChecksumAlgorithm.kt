package io.github.romantsisyk.cryptolib.integrity

/**
 * Enumeration of supported checksum algorithms for data integrity verification.
 *
 * This enum provides different checksum algorithms with varying levels of security and performance:
 * - CRC32: Fast, basic error detection (non-cryptographic)
 * - ADLER32: Fast, basic error detection (non-cryptographic)
 * - MD5: Cryptographic hash (deprecated for security-critical applications)
 * - SHA256: Strong cryptographic hash (recommended for security)
 * - SHA512: Stronger cryptographic hash with longer output
 */
enum class ChecksumAlgorithm(val algorithmName: String) {
    /**
     * CRC32 checksum algorithm.
     * Fast, suitable for basic error detection but not cryptographically secure.
     */
    CRC32("CRC32"),

    /**
     * ADLER32 checksum algorithm.
     * Faster than CRC32, suitable for basic error detection but not cryptographically secure.
     */
    ADLER32("ADLER32"),

    /**
     * MD5 message digest algorithm.
     * Cryptographic hash function, now considered weak for security purposes.
     * Use only for non-security critical checksums.
     */
    MD5("MD5"),

    /**
     * SHA-256 secure hash algorithm.
     * Strong cryptographic hash function, recommended for security-critical applications.
     */
    SHA256("SHA-256"),

    /**
     * SHA-512 secure hash algorithm.
     * Stronger cryptographic hash function with longer output (512 bits).
     */
    SHA512("SHA-512");

    companion object {
        /**
         * Returns the default checksum algorithm (SHA256).
         */
        fun default(): ChecksumAlgorithm = SHA256

        /**
         * Converts a string to a ChecksumAlgorithm enum value.
         * @param value The string representation of the algorithm.
         * @return The corresponding ChecksumAlgorithm, or null if not found.
         */
        fun fromString(value: String): ChecksumAlgorithm? {
            return entries.find { it.algorithmName.equals(value, ignoreCase = true) }
        }
    }
}
