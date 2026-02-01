package io.github.romantsisyk.cryptolib.storage

import android.content.Context
import java.io.File

/**
 * Example usage of the Secure Storage module.
 * This file demonstrates how to use SecurePreferences and SecureFileStorage
 * for encrypted data persistence.
 */
object SecureStorageExample {

    /**
     * Example: Using SecurePreferences for encrypted SharedPreferences.
     */
    fun securePreferencesExample(context: Context) {
        // Create SecurePreferences instance with default settings
        val securePrefs = SecurePreferences(context)

        // Store encrypted data
        securePrefs.putString("username", "john_doe")
        securePrefs.putString("api_key", "sk-1234567890abcdef")
        securePrefs.putInt("user_id", 42)
        securePrefs.putBoolean("is_premium", true)

        // Store binary data (e.g., encryption keys, tokens)
        val secretToken = "sensitive_data".toByteArray()
        securePrefs.putBytes("secret_token", secretToken)

        // Retrieve encrypted data
        val username = securePrefs.getString("username") // Returns "john_doe"
        val userId = securePrefs.getInt("user_id") // Returns 42
        val isPremium = securePrefs.getBoolean("is_premium") // Returns true
        val token = securePrefs.getBytes("secret_token") // Returns ByteArray

        // Check if a key exists
        if (securePrefs.contains("username")) {
            println("Username is stored")
        }

        // Get all stored keys
        val allKeys = securePrefs.getAllKeys()
        println("Stored keys: $allKeys")

        // Remove a specific key
        securePrefs.remove("old_key")

        // Clear all data
        // securePrefs.clear()
    }

    /**
     * Example: Using SecurePreferences with custom configuration.
     */
    fun securePreferencesWithConfigExample(context: Context) {
        // Create custom configuration
        val config = SecureStorageConfig.Builder("MyAppKey")
            .preferencesName("my_app_secure_prefs")
            .enableBackup(false)
            .autoCreateKey(true)
            .build()

        // Create SecurePreferences with custom key alias and preferences name
        val securePrefs = SecurePreferences(
            context,
            keyAlias = config.keyAlias,
            preferencesName = config.preferencesName
        )

        // Use as normal
        securePrefs.putString("session_token", "abc123xyz")
    }

    /**
     * Example: Using SecureFileStorage for encrypted file operations.
     */
    fun secureFileStorageExample(context: Context) {
        val secureStorage = SecureFileStorage()

        // Create file path
        val documentsDir = context.filesDir
        val secretFile = File(documentsDir, "secrets/api_config.enc")

        // Encrypt and write string to file
        val apiConfig = """
            {
                "api_key": "sk-1234567890",
                "api_secret": "secret-key-xyz",
                "endpoint": "https://api.example.com"
            }
        """.trimIndent()

        secureStorage.writeEncryptedString(secretFile, apiConfig)

        // Read and decrypt string from file
        val decryptedConfig = secureStorage.readDecryptedString(secretFile)
        println("Decrypted config: $decryptedConfig")

        // Encrypt and write binary data
        val binaryData = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val binaryFile = File(documentsDir, "binary_data.enc")
        secureStorage.writeEncrypted(binaryFile, binaryData)

        // Read and decrypt binary data
        val decryptedBinary = secureStorage.readDecrypted(binaryFile)

        // Check if file exists
        if (secureStorage.exists(secretFile)) {
            println("File exists")
        }

        // Get file size
        val size = secureStorage.getFileSize(secretFile)
        println("File size: $size bytes")

        // Delete file normally
        // secureStorage.delete(secretFile)

        // Securely delete file (overwrites before deletion)
        secureStorage.deleteSecurely(secretFile, overwritePasses = 3)
    }

    /**
     * Example: Using SecureFileStorage with custom key.
     */
    fun secureFileStorageWithCustomKeyExample(context: Context) {
        // Create SecureFileStorage with custom key alias
        val secureStorage = SecureFileStorage("MyAppFileEncryptionKey")

        val file = File(context.filesDir, "encrypted_data.bin")
        val data = "Sensitive information".toByteArray()

        secureStorage.writeEncrypted(file, data)
        val decrypted = secureStorage.readDecrypted(file)
    }

    /**
     * Example: Storing user credentials securely.
     */
    fun storeUserCredentialsExample(context: Context) {
        val securePrefs = SecurePreferences(context, "UserCredentialsKey")

        // Store login credentials
        securePrefs.putString("email", "user@example.com")
        securePrefs.putString("password_hash", "hashed_password_value")
        securePrefs.putString("auth_token", "bearer_token_xyz")
        securePrefs.putBoolean("remember_me", true)

        // Retrieve credentials
        val email = securePrefs.getString("email")
        val authToken = securePrefs.getString("auth_token")
        val rememberMe = securePrefs.getBoolean("remember_me")

        // Clear credentials on logout
        if (!rememberMe) {
            securePrefs.clear()
        }
    }

    /**
     * Example: Storing encryption keys in files.
     */
    fun storeEncryptionKeysExample(context: Context) {
        val secureStorage = SecureFileStorage("MasterEncryptionKey")

        // Generate a key (example)
        val userKey = ByteArray(32) { it.toByte() }

        // Store the key encrypted
        val keyFile = File(context.filesDir, "keys/user_encryption_key.bin")
        secureStorage.writeEncrypted(keyFile, userKey)

        // Later, retrieve the key
        val retrievedKey = secureStorage.readDecrypted(keyFile)

        // When no longer needed, securely delete
        secureStorage.deleteSecurely(keyFile)
    }

    /**
     * Example: Combining SecurePreferences and SecureFileStorage.
     */
    fun combinedStorageExample(context: Context) {
        val securePrefs = SecurePreferences(context, "AppConfig")
        val secureFiles = SecureFileStorage("AppFiles")

        // Store configuration in preferences
        securePrefs.putString("server_url", "https://api.example.com")
        securePrefs.putInt("timeout_seconds", 30)

        // Store larger data in files
        val userData = """
            {
                "name": "John Doe",
                "preferences": {...},
                "history": [...]
            }
        """.trimIndent()

        val userFile = File(context.filesDir, "user_data.json.enc")
        secureFiles.writeEncryptedString(userFile, userData)

        // Retrieve data
        val serverUrl = securePrefs.getString("server_url")
        val userDataDecrypted = secureFiles.readDecryptedString(userFile)
    }

    /**
     * Example: Migration from unencrypted to encrypted storage.
     */
    fun migrationExample(context: Context) {
        // Read from old unencrypted SharedPreferences
        val oldPrefs = context.getSharedPreferences("old_prefs", Context.MODE_PRIVATE)
        val oldValue = oldPrefs.getString("key", null)

        if (oldValue != null) {
            // Migrate to encrypted storage
            val securePrefs = SecurePreferences(context)
            securePrefs.putString("key", oldValue)

            // Remove from old storage
            oldPrefs.edit().remove("key").apply()
        }
    }

    /**
     * Example: Error handling.
     */
    fun errorHandlingExample(context: Context) {
        val securePrefs = SecurePreferences(context)
        val secureFiles = SecureFileStorage()

        try {
            // This will work normally
            securePrefs.putString("key", "value")
            val retrieved = securePrefs.getString("key")
        } catch (e: Exception) {
            // Handle encryption/decryption errors
            println("Error with secure preferences: ${e.message}")
        }

        try {
            val file = File(context.filesDir, "data.enc")
            secureFiles.writeEncryptedString(file, "data")
            val data = secureFiles.readDecryptedString(file)
        } catch (e: Exception) {
            // Handle file I/O or encryption errors
            println("Error with secure file storage: ${e.message}")
        }
    }
}
