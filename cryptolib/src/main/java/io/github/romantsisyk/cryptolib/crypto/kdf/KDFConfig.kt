package io.github.romantsisyk.cryptolib.crypto.kdf

/**
 * Configuration class for Key Derivation Function (KDF) operations.
 * This class encapsulates settings for iterations, key length, and the algorithm to use.
 *
 * @property iterations The number of iterations for the KDF algorithm (higher is more secure but slower).
 * @property keyLength The desired key length in bits.
 * @property algorithm The KDF algorithm to use.
 */
class KDFConfig private constructor(
    val iterations: Int,
    val keyLength: Int,
    val algorithm: KDFAlgorithm
) {

    /**
     * Builder class for creating an instance of [KDFConfig].
     * The builder pattern is used to allow setting optional configuration properties in a fluent way.
     */
    class Builder {
        // Default values for the configuration properties
        private var iterations: Int = DEFAULT_ITERATIONS
        private var keyLength: Int = DEFAULT_KEY_LENGTH
        private var algorithm: KDFAlgorithm = DEFAULT_ALGORITHM

        /**
         * Set the number of iterations for the KDF algorithm.
         * Higher iteration counts provide better security but require more computation time.
         *
         * @param iterations The number of iterations (must be positive).
         * @return The current [Builder] instance for fluent chaining.
         */
        fun iterations(iterations: Int) = apply {
            this.iterations = iterations
        }

        /**
         * Set the desired key length in bits.
         *
         * @param keyLength The key length in bits (must be positive and a multiple of 8).
         * @return The current [Builder] instance for fluent chaining.
         */
        fun keyLength(keyLength: Int) = apply {
            this.keyLength = keyLength
        }

        /**
         * Set the KDF algorithm to use.
         *
         * @param algorithm The KDF algorithm.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun algorithm(algorithm: KDFAlgorithm) = apply {
            this.algorithm = algorithm
        }

        /**
         * Build the [KDFConfig] object with the set properties.
         *
         * @return A new [KDFConfig] instance.
         * @throws IllegalArgumentException if validation fails for any of the configuration properties.
         */
        fun build(): KDFConfig {
            require(iterations > 0) {
                "iterations must be greater than 0, but was $iterations"
            }
            require(iterations >= MIN_ITERATIONS) {
                "iterations should be at least $MIN_ITERATIONS for security, but was $iterations"
            }
            require(keyLength > 0) {
                "keyLength must be greater than 0, but was $keyLength"
            }
            require(keyLength % 8 == 0) {
                "keyLength must be a multiple of 8, but was $keyLength"
            }
            require(keyLength >= MIN_KEY_LENGTH) {
                "keyLength should be at least $MIN_KEY_LENGTH bits for security, but was $keyLength"
            }
            return KDFConfig(iterations, keyLength, algorithm)
        }
    }

    companion object {
        /**
         * Default number of iterations (600,000 for PBKDF2-HMAC-SHA256 per OWASP 2023 guidelines).
         * See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
         */
        const val DEFAULT_ITERATIONS = 600_000

        /**
         * Minimum recommended iterations for security (210,000 per OWASP 2023 for PBKDF2-HMAC-SHA512).
         */
        const val MIN_ITERATIONS = 210_000

        /**
         * Default key length in bits (256 bits = 32 bytes).
         */
        const val DEFAULT_KEY_LENGTH = 256

        /**
         * Minimum recommended key length in bits.
         */
        const val MIN_KEY_LENGTH = 128

        /**
         * Default KDF algorithm.
         */
        val DEFAULT_ALGORITHM = KDFAlgorithm.PBKDF2_SHA256

        /**
         * Creates a default [KDFConfig] with recommended security settings.
         *
         * @return A new [KDFConfig] instance with default settings.
         */
        fun getDefault(): KDFConfig {
            return Builder().build()
        }
    }
}
