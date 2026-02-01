# Secure Storage Module

The Secure Storage module provides encrypted data persistence for Android applications using the CryptoKit library. It includes encrypted SharedPreferences and encrypted file storage capabilities.

## Features

- **SecurePreferences**: Encrypted wrapper around SharedPreferences
- **SecureFileStorage**: Encrypted file read/write operations
- **SecureStorageConfig**: Configuration builder for customization
- Automatic key management using Android Keystore
- Secure file deletion with data overwriting
- Support for strings, integers, booleans, and byte arrays

## Components

### 1. SecurePreferences

Encrypted SharedPreferences wrapper that automatically encrypts all values before storage.

**Key Features:**
- Transparent encryption/decryption
- Type-safe methods for common data types
- Automatic key generation and management
- Compatible with standard SharedPreferences API

**Usage:**

```kotlin
// Create instance with default settings
val securePrefs = SecurePreferences(context)

// Store encrypted data
securePrefs.putString("api_key", "sk-1234567890")
securePrefs.putInt("user_id", 42)
securePrefs.putBoolean("is_premium", true)
securePrefs.putBytes("token", byteArrayOf(0x01, 0x02, 0x03))

// Retrieve decrypted data
val apiKey = securePrefs.getString("api_key")
val userId = securePrefs.getInt("user_id")
val isPremium = securePrefs.getBoolean("is_premium")
val token = securePrefs.getBytes("token")

// Check existence
if (securePrefs.contains("api_key")) {
    // Key exists
}

// Remove key
securePrefs.remove("api_key")

// Clear all data
securePrefs.clear()
```

**Custom Configuration:**

```kotlin
val securePrefs = SecurePreferences(
    context = context,
    keyAlias = "MyCustomKey",
    preferencesName = "my_secure_prefs"
)
```

### 2. SecureFileStorage

Encrypted file storage for reading and writing encrypted files.

**Key Features:**
- Encrypt data before writing to disk
- Decrypt data when reading from disk
- Secure file deletion with overwriting
- Support for both strings and binary data
- Automatic directory creation

**Usage:**

```kotlin
val secureStorage = SecureFileStorage()

// Write encrypted string to file
val configData = """{"api_key": "secret", "endpoint": "https://api.example.com"}"""
val file = File(context.filesDir, "config.enc")
secureStorage.writeEncryptedString(file, configData)

// Read and decrypt string from file
val decryptedConfig = secureStorage.readDecryptedString(file)

// Write encrypted binary data
val binaryData = byteArrayOf(0x01, 0x02, 0x03)
secureStorage.writeEncrypted(file, binaryData)

// Read and decrypt binary data
val decryptedBinary = secureStorage.readDecrypted(file)

// Securely delete file (overwrites before deletion)
secureStorage.deleteSecurely(file, overwritePasses = 3)
```

**Custom Key:**

```kotlin
val secureStorage = SecureFileStorage("CustomFileEncryptionKey")
```

### 3. SecureStorageConfig

Configuration builder for customizing storage behavior.

**Usage:**

```kotlin
val config = SecureStorageConfig.Builder("MyAppKey")
    .preferencesName("my_app_secure_prefs")
    .enableBackup(false)
    .autoCreateKey(true)
    .build()

val securePrefs = SecurePreferences(
    context,
    keyAlias = config.keyAlias,
    preferencesName = config.preferencesName
)
```

## Common Use Cases

### Storing User Credentials

```kotlin
val securePrefs = SecurePreferences(context, "UserCredentials")

// Store credentials
securePrefs.putString("email", "user@example.com")
securePrefs.putString("auth_token", "bearer_token_xyz")
securePrefs.putBoolean("remember_me", true)

// Retrieve credentials
val email = securePrefs.getString("email")
val authToken = securePrefs.getString("auth_token")

// Clear on logout
if (!securePrefs.getBoolean("remember_me")) {
    securePrefs.clear()
}
```

### Storing API Keys

```kotlin
val secureStorage = SecureFileStorage()
val keyFile = File(context.filesDir, "keys/api_key.enc")

// Store encrypted API key
secureStorage.writeEncryptedString(keyFile, "sk-abc123xyz")

// Retrieve API key
val apiKey = secureStorage.readDecryptedString(keyFile)

// Delete when no longer needed
secureStorage.deleteSecurely(keyFile)
```

### Storing Encryption Keys

```kotlin
val secureStorage = SecureFileStorage("MasterKey")

// Generate and store a key
val encryptionKey = ByteArray(32) { it.toByte() }
val keyFile = File(context.filesDir, "encryption_key.bin")
secureStorage.writeEncrypted(keyFile, encryptionKey)

// Retrieve key
val retrievedKey = secureStorage.readDecrypted(keyFile)

// Securely delete
secureStorage.deleteSecurely(keyFile)
```

### Migration from Unencrypted Storage

```kotlin
// Read from old SharedPreferences
val oldPrefs = context.getSharedPreferences("old_prefs", Context.MODE_PRIVATE)
val oldData = oldPrefs.getString("sensitive_data", null)

if (oldData != null) {
    // Migrate to encrypted storage
    val securePrefs = SecurePreferences(context)
    securePrefs.putString("sensitive_data", oldData)

    // Remove from old storage
    oldPrefs.edit().remove("sensitive_data").apply()
}
```

## Security Considerations

1. **Key Storage**: All encryption keys are stored in the Android Keystore, which provides hardware-backed security on supported devices.

2. **Key Validity**: Keys are created with a long validity period (10 years by default) to prevent expiration issues.

3. **User Authentication**: By default, user authentication is not required for key access. You can modify this in `KeyHelper.generateAESKey()`.

4. **Secure Deletion**: The `deleteSecurely()` method overwrites file contents before deletion to prevent data recovery.

5. **Backup**: By default, encrypted data backup is disabled. Enable with caution.

6. **Thread Safety**: Both `SecurePreferences` and `SecureFileStorage` are thread-safe for concurrent reads, but writes should be synchronized if needed.

## Error Handling

All operations may throw `CryptoOperationException` or `IOException`:

```kotlin
try {
    securePrefs.putString("key", "value")
    val value = securePrefs.getString("key")
} catch (e: CryptoOperationException) {
    // Handle encryption/decryption errors
    Log.e("SecureStorage", "Encryption error", e)
}

try {
    secureStorage.writeEncryptedString(file, "data")
    val data = secureStorage.readDecryptedString(file)
} catch (e: IOException) {
    // Handle file I/O errors
    Log.e("SecureStorage", "File error", e)
} catch (e: CryptoOperationException) {
    // Handle encryption errors
    Log.e("SecureStorage", "Encryption error", e)
}
```

## Performance Considerations

1. **Encryption Overhead**: Each read/write operation involves encryption/decryption. Cache frequently accessed data in memory when appropriate.

2. **Key Initialization**: The first access to `SecurePreferences` or `SecureFileStorage` initializes the key, which may take a few milliseconds.

3. **File Size**: For large files, consider streaming encryption for better memory efficiency.

4. **Secure Deletion**: Multiple overwrite passes increase deletion time. Use fewer passes (1-3) for better performance.

## Testing

The module includes comprehensive unit tests:

- `SecureStorageConfigTest`: Configuration builder tests
- `SecurePreferencesTest`: Encrypted preferences tests
- `SecureFileStorageTest`: Encrypted file storage tests

Run tests with:
```bash
./gradlew :cryptolib:test
```

## Dependencies

- Android Keystore (android.security.keystore)
- AESEncryption (cryptolib.crypto.aes)
- KeyHelper (cryptolib.crypto.keymanagement)
- CryptoOperationException (cryptolib.exceptions)

## Example

See `SecureStorageExample.kt` for comprehensive usage examples.
