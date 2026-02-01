package io.github.romantsisyk.cryptolib.storage

/**
 * Configuration class for managing secure storage settings.
 * This class encapsulates settings for key alias, shared preferences name, and encryption behavior.
 * It's used to configure how data is securely stored and encrypted in the system.
 *
 * @property keyAlias The alias under which the cryptographic key is stored.
 * @property preferencesName The name of the SharedPreferences file.
 * @property enableBackup Flag indicating whether to allow backup of encrypted data.
 * @property autoCreateKey Flag indicating whether to automatically create key if not found.
 */
class SecureStorageConfig private constructor(
    val keyAlias: String,
    val preferencesName: String,
    val enableBackup: Boolean,
    val autoCreateKey: Boolean
) {

    /**
     * Builder class for creating an instance of [SecureStorageConfig].
     * The builder pattern is used to allow setting optional configuration properties in a fluent way.
     *
     * @param keyAlias The alias used to store and retrieve the cryptographic key.
     */
    data class Builder(
        private val keyAlias: String
    ) {
        // Default values for the configuration properties
        private var preferencesName: String = "secure_prefs"
        private var enableBackup: Boolean = false
        private var autoCreateKey: Boolean = true

        /**
         * Set the name of the SharedPreferences file.
         *
         * @param name The name for the SharedPreferences file.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun preferencesName(name: String) = apply {
            this.preferencesName = name
        }

        /**
         * Set whether backup of encrypted data should be allowed.
         *
         * @param enable True if backup should be allowed, false otherwise.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun enableBackup(enable: Boolean) = apply {
            this.enableBackup = enable
        }

        /**
         * Set whether to automatically create the key if it doesn't exist.
         *
         * @param autoCreate True to auto-create key, false otherwise.
         * @return The current [Builder] instance for fluent chaining.
         */
        fun autoCreateKey(autoCreate: Boolean) = apply {
            this.autoCreateKey = autoCreate
        }

        /**
         * Build the [SecureStorageConfig] object with the set properties.
         *
         * @return A new [SecureStorageConfig] instance.
         * @throws IllegalArgumentException if validation fails for any of the configuration properties.
         */
        fun build(): SecureStorageConfig {
            require(keyAlias.isNotBlank()) {
                "keyAlias cannot be empty or blank"
            }
            require(preferencesName.isNotBlank()) {
                "preferencesName cannot be empty or blank"
            }
            return SecureStorageConfig(
                keyAlias,
                preferencesName,
                enableBackup,
                autoCreateKey
            )
        }
    }

    companion object {
        /**
         * Default key alias for secure storage.
         */
        const val DEFAULT_KEY_ALIAS = "SecureStorageKey"

        /**
         * Default SharedPreferences name.
         */
        const val DEFAULT_PREFERENCES_NAME = "secure_prefs"
    }
}
