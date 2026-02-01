package io.github.romantsisyk.cryptolib.storage

import android.content.Context
import android.content.SharedPreferences
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64
import javax.crypto.SecretKey

/**
 * Encrypted SharedPreferences wrapper for secure data persistence.
 * This class provides a secure way to store key-value pairs by encrypting all values
 * before storing them in SharedPreferences.
 *
 * @property context The Android context used to access SharedPreferences.
 * @property keyAlias The alias for the encryption key (default: "SecureStorageKey").
 * @property preferencesName The name of the SharedPreferences file (default: "secure_prefs").
 */
class SecurePreferences(
    private val context: Context,
    private val keyAlias: String = SecureStorageConfig.DEFAULT_KEY_ALIAS,
    private val preferencesName: String = SecureStorageConfig.DEFAULT_PREFERENCES_NAME
) {

    private val sharedPreferences: SharedPreferences =
        context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)

    private val secretKey: SecretKey by lazy {
        initializeKey()
    }

    /**
     * Initializes the encryption key. If the key doesn't exist, it will be created.
     *
     * @return The SecretKey used for encryption and decryption.
     * @throws CryptoOperationException if key initialization fails.
     */
    private fun initializeKey(): SecretKey {
        return try {
            // Try to get existing key
            try {
                KeyHelper.getAESKey(keyAlias)
            } catch (e: Exception) {
                // Key doesn't exist, generate a new one
                KeyHelper.generateAESKey(
                    alias = keyAlias,
                    validityDays = 3650, // 10 years
                    requireUserAuthentication = false
                )
                KeyHelper.getAESKey(keyAlias)
            }
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to initialize encryption key", e)
        }
    }

    /**
     * Stores an encrypted string value.
     *
     * @param key The key under which the value is stored.
     * @param value The string value to encrypt and store.
     * @throws CryptoOperationException if encryption fails.
     */
    fun putString(key: String, value: String) {
        try {
            val encrypted = AESEncryption.encrypt(value.toByteArray(Charsets.UTF_8), secretKey)
            sharedPreferences.edit().putString(key, encrypted).apply()
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to encrypt and store string for key: $key", e)
        }
    }

    /**
     * Retrieves and decrypts a string value.
     *
     * @param key The key under which the value is stored.
     * @param defaultValue The default value to return if the key doesn't exist.
     * @return The decrypted string value, or the default value if the key doesn't exist.
     * @throws CryptoOperationException if decryption fails.
     */
    fun getString(key: String, defaultValue: String? = null): String? {
        val encrypted = sharedPreferences.getString(key, null) ?: return defaultValue
        return try {
            val decrypted = AESEncryption.decrypt(encrypted, secretKey)
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to decrypt string for key: $key", e)
        }
    }

    /**
     * Stores an encrypted integer value.
     *
     * @param key The key under which the value is stored.
     * @param value The integer value to encrypt and store.
     * @throws CryptoOperationException if encryption fails.
     */
    fun putInt(key: String, value: Int) {
        try {
            val valueString = value.toString()
            val encrypted = AESEncryption.encrypt(valueString.toByteArray(Charsets.UTF_8), secretKey)
            sharedPreferences.edit().putString(key, encrypted).apply()
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to encrypt and store int for key: $key", e)
        }
    }

    /**
     * Retrieves and decrypts an integer value.
     *
     * @param key The key under which the value is stored.
     * @param defaultValue The default value to return if the key doesn't exist.
     * @return The decrypted integer value, or the default value if the key doesn't exist.
     * @throws CryptoOperationException if decryption fails.
     */
    fun getInt(key: String, defaultValue: Int = 0): Int {
        val encrypted = sharedPreferences.getString(key, null) ?: return defaultValue
        return try {
            val decrypted = AESEncryption.decrypt(encrypted, secretKey)
            String(decrypted, Charsets.UTF_8).toInt()
        } catch (e: NumberFormatException) {
            throw CryptoOperationException("Failed to parse int for key: $key", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to decrypt int for key: $key", e)
        }
    }

    /**
     * Stores an encrypted boolean value.
     *
     * @param key The key under which the value is stored.
     * @param value The boolean value to encrypt and store.
     * @throws CryptoOperationException if encryption fails.
     */
    fun putBoolean(key: String, value: Boolean) {
        try {
            val valueString = value.toString()
            val encrypted = AESEncryption.encrypt(valueString.toByteArray(Charsets.UTF_8), secretKey)
            sharedPreferences.edit().putString(key, encrypted).apply()
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to encrypt and store boolean for key: $key", e)
        }
    }

    /**
     * Retrieves and decrypts a boolean value.
     *
     * @param key The key under which the value is stored.
     * @param defaultValue The default value to return if the key doesn't exist.
     * @return The decrypted boolean value, or the default value if the key doesn't exist.
     * @throws CryptoOperationException if decryption fails.
     */
    fun getBoolean(key: String, defaultValue: Boolean = false): Boolean {
        val encrypted = sharedPreferences.getString(key, null) ?: return defaultValue
        return try {
            val decrypted = AESEncryption.decrypt(encrypted, secretKey)
            String(decrypted, Charsets.UTF_8).toBoolean()
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to decrypt boolean for key: $key", e)
        }
    }

    /**
     * Stores encrypted byte array data.
     *
     * @param key The key under which the value is stored.
     * @param value The byte array to encrypt and store.
     * @throws CryptoOperationException if encryption fails.
     */
    fun putBytes(key: String, value: ByteArray) {
        try {
            val encrypted = AESEncryption.encrypt(value, secretKey)
            sharedPreferences.edit().putString(key, encrypted).apply()
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to encrypt and store bytes for key: $key", e)
        }
    }

    /**
     * Retrieves and decrypts a byte array.
     *
     * @param key The key under which the value is stored.
     * @return The decrypted byte array, or null if the key doesn't exist.
     * @throws CryptoOperationException if decryption fails.
     */
    fun getBytes(key: String): ByteArray? {
        val encrypted = sharedPreferences.getString(key, null) ?: return null
        return try {
            AESEncryption.decrypt(encrypted, secretKey)
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to decrypt bytes for key: $key", e)
        }
    }

    /**
     * Removes a key-value pair from the encrypted storage.
     *
     * @param key The key to remove.
     */
    fun remove(key: String) {
        sharedPreferences.edit().remove(key).apply()
    }

    /**
     * Clears all key-value pairs from the encrypted storage.
     */
    fun clear() {
        sharedPreferences.edit().clear().apply()
    }

    /**
     * Checks if a key exists in the encrypted storage.
     *
     * @param key The key to check.
     * @return True if the key exists, false otherwise.
     */
    fun contains(key: String): Boolean {
        return sharedPreferences.contains(key)
    }

    /**
     * Returns all keys stored in the encrypted storage.
     *
     * @return A set of all keys.
     */
    fun getAllKeys(): Set<String> {
        return sharedPreferences.all.keys
    }
}
