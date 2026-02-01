package io.github.romantsisyk.cryptolib.crypto.config

/**
 * Configuration class for managing cryptographic settings.
 * This class encapsulates settings for key alias, user authentication requirement, key rotation interval, and key validity period.
 * It's used to set up the conditions under which keys are managed and rotated in the system.
 *
 * @property keyAlias The alias under which the cryptographic key is stored.
 * @property requireUserAuthentication Flag indicating whether user authentication is required for key access.
 * @property keyRotationIntervalDays The number of days after which the key should be rotated.
 * @property keyValidityDays The number of days the key is considered valid before it needs to be replaced.
 */
class CryptoConfig private constructor(
    val keyAlias: String,
    val requireUserAuthentication: Boolean,
    val keyRotationIntervalDays: Int,
    val keyValidityDays: Int
) {

    /**
     * Builder class for creating an instance of [CryptoConfig].
     * The builder pattern is used to allow setting optional configuration properties in a fluent way.
     *
     * @param keyAlias The alias used to store and retrieve the cryptographic key.
     */
    data class Builder(
        private val keyAlias: String
    ) {
        // Default values for the configuration properties
        private var requireUserAuthentication: Boolean = false
        private var keyRotationIntervalDays: Int = 90
        private var keyValidityDays: Int = 365

        /**
         * Set whether user authentication is required to access the cryptographic key.
         *
         * @param requireAuth True if user authentication should be required, false otherwise.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun requireUserAuthentication(requireAuth: Boolean) = apply {
            this.requireUserAuthentication = requireAuth
        }

        /**
         * Set the number of days after which the key should be rotated.
         *
         * @param days The number of days for key rotation.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun keyRotationIntervalDays(days: Int) = apply {
            this.keyRotationIntervalDays = days
        }

        /**
         * Set the number of days the key will be valid before it needs to be replaced.
         *
         * @param days The number of days for key validity.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun keyValidityDays(days: Int) = apply {
            this.keyValidityDays = days
        }

        /**
         * Build the [CryptoConfig] object with the set properties.
         *
         * @return A new [CryptoConfig] instance.
         * @throws IllegalArgumentException if validation fails for any of the configuration properties.
         */
        fun build(): CryptoConfig {
            require(keyAlias.isNotBlank()) {
                "keyAlias cannot be empty or blank"
            }
            require(keyRotationIntervalDays > 0) {
                "keyRotationIntervalDays must be greater than 0, but was $keyRotationIntervalDays"
            }
            require(keyValidityDays > 0) {
                "keyValidityDays must be greater than 0, but was $keyValidityDays"
            }
            require(keyRotationIntervalDays <= keyValidityDays) {
                "keyRotationIntervalDays ($keyRotationIntervalDays) must be less than or equal to keyValidityDays ($keyValidityDays)"
            }
            return CryptoConfig(
                keyAlias,
                requireUserAuthentication,
                keyRotationIntervalDays,
                keyValidityDays
            )
        }
    }
}