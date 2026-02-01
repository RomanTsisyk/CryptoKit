# Secure Random Module

The Secure Random module provides cryptographically secure random number generation for the CryptoKit library. All classes use `java.security.SecureRandom` to ensure cryptographic strength.

## Components

### 1. SecureRandomGenerator

Core utility for generating cryptographically secure random values.

**Methods:**
- `generateBytes(length: Int): ByteArray` - Generate random bytes
- `generateInt(): Int` - Generate random integer
- `generateInt(bound: Int): Int` - Generate random integer with upper bound
- `generateInt(min: Int, max: Int): Int` - Generate random integer in range
- `generateLong(): Long` - Generate random long
- `generateLong(min: Long, max: Long): Long` - Generate random long in range
- `generateDouble(): Double` - Generate random double (0.0 to 1.0)
- `generateBoolean(): Boolean` - Generate random boolean
- `generateUUID(): String` - Generate random UUID v4
- `shuffle(list: MutableList<T>): MutableList<T>` - Cryptographically shuffle a list

**Examples:**
```kotlin
// Generate 32 random bytes
val bytes = SecureRandomGenerator.generateBytes(32)

// Generate random integer between 1 and 100 (inclusive)
val number = SecureRandomGenerator.generateInt(1, 100)

// Generate random UUID
val uuid = SecureRandomGenerator.generateUUID()

// Shuffle a list
val items = mutableListOf("A", "B", "C", "D")
SecureRandomGenerator.shuffle(items)
```

### 2. RandomStringGenerator

Generate cryptographically secure random strings in various formats.

**Methods:**
- `generateAlphanumeric(length: Int): String` - A-Z, a-z, 0-9
- `generateAlphabetic(length: Int): String` - A-Z, a-z
- `generateNumeric(length: Int): String` - 0-9
- `generateHex(length: Int): String` - 0-9, a-f
- `generateBase64(byteLength: Int): String` - Base64 encoded random bytes
- `generateFromCharset(length: Int, charset: String): String` - Custom character set
- `generatePassword(length: Int, includeUppercase: Boolean, includeLowercase: Boolean, includeDigits: Boolean, includeSpecial: Boolean): String` - Secure password

**Examples:**
```kotlin
// Generate alphanumeric string
val code = RandomStringGenerator.generateAlphanumeric(12)

// Generate hex string
val hex = RandomStringGenerator.generateHex(32)

// Generate secure password
val password = RandomStringGenerator.generatePassword(
    length = 16,
    includeUppercase = true,
    includeLowercase = true,
    includeDigits = true,
    includeSpecial = true
)

// Generate from custom charset
val customString = RandomStringGenerator.generateFromCharset(10, "ABCXYZ123")
```

### 3. IVGenerator

Generate Initialization Vectors (IVs) and nonces for encryption operations.

**Methods:**
- `generateIV(size: Int = 12): ByteArray` - Generate IV (default 12 bytes for GCM)
- `generateIV16(): ByteArray` - Generate 16-byte IV (for CBC)
- `generateNonce(size: Int = 12): ByteArray` - Generate nonce

**Examples:**
```kotlin
// Generate IV for AES-GCM (12 bytes recommended)
val ivGCM = IVGenerator.generateIV()

// Generate IV for AES-CBC (16 bytes - block size)
val ivCBC = IVGenerator.generateIV16()

// Generate custom size nonce
val nonce = IVGenerator.generateNonce(24)
```

### 4. SaltGenerator

Generate salts for password hashing and key derivation.

**Methods:**
- `generateSalt(length: Int = 32): ByteArray` - Generate salt as bytes
- `generateSaltHex(length: Int = 32): String` - Generate salt as hex string
- `generateSaltBase64(length: Int = 32): String` - Generate salt as Base64 string

**Examples:**
```kotlin
// Generate 32-byte salt (recommended for password hashing)
val salt = SaltGenerator.generateSalt()

// Generate salt as hex string (64 characters for 32 bytes)
val saltHex = SaltGenerator.generateSaltHex()

// Generate salt as Base64 string
val saltBase64 = SaltGenerator.generateSaltBase64()

// Generate custom length salt
val salt16 = SaltGenerator.generateSalt(16)
```

## Security Considerations

1. **SecureRandom Initialization**: All classes use `SecureRandom.getInstanceStrong()` with fallback to default `SecureRandom()` for maximum security.

2. **IV/Nonce Uniqueness**: Always generate a new IV or nonce for each encryption operation. Never reuse IVs with the same key.

3. **Salt Storage**: Salts should be stored alongside hashed passwords. They don't need to be secret but must be unique per password.

4. **Password Generation**: The `generatePassword()` method ensures at least one character from each enabled character type is included and then shuffles the result.

5. **Random Range**: When generating integers or longs in a range, the implementation uses secure methods to avoid modulo bias.

## Integration with CryptoKit

The Secure Random module integrates seamlessly with other CryptoKit components:

```kotlin
// Generate IV for AES encryption
val iv = IVGenerator.generateIV()
val key = AESEncryption.generateKey()
val plaintext = "Secret message".toByteArray()

// Use IV in encryption (conceptual - actual API may vary)
// val encrypted = AESEncryption.encrypt(plaintext, key, iv)

// Generate salt for password hashing
val salt = SaltGenerator.generateSalt()
val password = "user_password"
// val hashedPassword = PasswordHasher.hash(password, salt)

// Generate secure random key material
val keyMaterial = SecureRandomGenerator.generateBytes(32)
```

## Error Handling

All methods throw `CryptoOperationException` for invalid parameters or errors:

```kotlin
try {
    val bytes = SecureRandomGenerator.generateBytes(-1)
} catch (e: CryptoOperationException) {
    // Handle error: "Random byte generation failed: length must be positive"
}
```

## Best Practices

1. **Use appropriate sizes**:
   - IVs: 12 bytes for GCM, 16 bytes for CBC
   - Salts: 32 bytes minimum for password hashing
   - Passwords: 12+ characters with mixed character types

2. **Don't reuse cryptographic values**:
   - Generate new IVs for each encryption
   - Generate unique salts for each password

3. **Choose appropriate methods**:
   - Use `IVGenerator` for encryption IVs
   - Use `SaltGenerator` for password salts
   - Use `RandomStringGenerator.generatePassword()` for passwords
   - Use `SecureRandomGenerator` for general random values

4. **Validate inputs**: All methods validate inputs and throw meaningful exceptions for invalid parameters.
