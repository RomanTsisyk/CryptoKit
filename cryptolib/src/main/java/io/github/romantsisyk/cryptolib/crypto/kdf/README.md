# Key Derivation Function (KDF) Module

This module provides secure password-based key derivation functionality for the CryptoKit library.

## Overview

The KDF module allows you to:
- Derive cryptographic keys from passwords using industry-standard algorithms (PBKDF2)
- Generate cryptographically secure random salts
- Validate password strength
- Check password requirements compliance

## Components

### 1. KDFAlgorithm
Enum defining supported KDF algorithms:
- `PBKDF2_SHA256` - PBKDF2 with HMAC-SHA256 (recommended for most uses)
- `PBKDF2_SHA512` - PBKDF2 with HMAC-SHA512 (higher security)

### 2. KDFConfig
Configuration class using the builder pattern:
- `iterations` - Number of iterations (default: 100,000)
- `keyLength` - Derived key length in bits (default: 256)
- `algorithm` - KDF algorithm to use (default: PBKDF2_SHA256)

### 3. KeyDerivation
Main class for key derivation operations:
- `deriveKey()` - Derive a key from password and salt
- `generateSalt()` - Generate cryptographically secure salt
- `deriveKeyWithNewSalt()` - Convenience method combining both operations

### 4. PasswordStrengthChecker
Utility for password validation:
- `checkStrength()` - Assess password strength (WEAK, FAIR, STRONG, VERY_STRONG)
- `meetsMinimumRequirements()` - Check if password meets specified criteria
- `validatePassword()` - Get detailed validation errors

### 5. PasswordStrength
Enum representing password strength levels:
- `WEAK` - Easily guessable or too short
- `FAIR` - Meets basic requirements
- `STRONG` - Good security
- `VERY_STRONG` - Excellent security

## Usage Examples

### Basic Key Derivation

```kotlin
// Use default configuration
val config = KDFConfig.getDefault()

// Derive key with new salt
val password = "MySecurePassword123!"
val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)

// Store the salt for later verification
// Use the key for encryption
```

### Custom Configuration

```kotlin
val config = KDFConfig.Builder()
    .iterations(200000)  // More iterations = more secure but slower
    .keyLength(512)      // 512-bit key
    .algorithm(KDFAlgorithm.PBKDF2_SHA512)
    .build()

val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)
```

### Password Verification

```kotlin
// Registration: derive and store
val (originalKey, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)
// Store salt in database

// Login: verify password
val loginKey = KeyDerivation.deriveKey(loginPassword, salt, config)
val isValid = Arrays.equals(originalKey.encoded, loginKey.encoded)
```

### Secure Password Handling with CharArray

```kotlin
val passwordChars = userInput.toCharArray()
try {
    val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(passwordChars, config)
    // Use key...
} finally {
    passwordChars.fill('\u0000')  // Clear password from memory
}
```

### Password Strength Checking

```kotlin
// Check strength
val strength = PasswordStrengthChecker.checkStrength(password)
when (strength) {
    PasswordStrength.WEAK -> println("Password is too weak")
    PasswordStrength.FAIR -> println("Password is acceptable")
    PasswordStrength.STRONG -> println("Password is strong")
    PasswordStrength.VERY_STRONG -> println("Password is very strong")
}

// Check minimum requirements
val meetsRequirements = PasswordStrengthChecker.meetsMinimumRequirements(
    password,
    minLength = 8,
    requireUppercase = true,
    requireDigit = true,
    requireSpecial = true
)

// Get detailed validation errors
val errors = PasswordStrengthChecker.validatePassword(password)
if (errors.isNotEmpty()) {
    errors.forEach { println(it) }
}
```

## Security Best Practices

### 1. Iteration Count
- Use at least 100,000 iterations (OWASP recommendation as of 2023)
- Higher is more secure but slower
- Balance security needs with performance requirements

### 2. Salt Management
- Always use a unique salt for each password
- Minimum salt length: 16 bytes (128 bits)
- Recommended: 32 bytes (256 bits)
- Store salt alongside hashed password (it doesn't need to be secret)

### 3. Key Length
- Minimum: 128 bits
- Recommended: 256 bits
- High security: 512 bits

### 4. Password Requirements
- Minimum length: 8 characters (12+ recommended)
- Require mixed character types (uppercase, lowercase, digits, special)
- Check against common password lists
- Avoid sequential or repeated characters

### 5. Memory Security
- Use `CharArray` instead of `String` for passwords when possible
- Clear password arrays after use: `passwordChars.fill('\u0000')`
- Never log passwords or derived keys

## Algorithm Details

### PBKDF2 (Password-Based Key Derivation Function 2)
- Industry standard defined in RFC 8018
- Uses multiple iterations of HMAC with a pseudorandom function
- Resistant to rainbow table and brute-force attacks
- Computational cost scales with iteration count

## Error Handling

All methods throw appropriate exceptions:
- `CryptoOperationException` - For key derivation failures
- `IllegalArgumentException` - For invalid parameters (empty password, short salt, etc.)

## Integration with CryptoKit

The derived keys are compatible with other CryptoKit modules:

```kotlin
// Derive key from password
val config = KDFConfig.getDefault()
val (derivedKey, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)

// Use with AESEncryption
val encrypted = AESEncryption.encrypt(plaintext, derivedKey)
val decrypted = AESEncryption.decrypt(encrypted, derivedKey)
```

## Performance Considerations

Key derivation is intentionally slow to resist brute-force attacks:
- 100,000 iterations: ~100-300ms on modern devices
- 200,000 iterations: ~200-600ms on modern devices

This is acceptable for user authentication but not suitable for high-frequency operations.

## Thread Safety

All methods in `KeyDerivation` and `PasswordStrengthChecker` are thread-safe as they use:
- Immutable configuration objects
- No shared mutable state
- Thread-safe `SecureRandom` instance

## Testing

Comprehensive unit tests are provided in the test package:
- `KDFAlgorithmTest` - Algorithm enum tests
- `KDFConfigTest` - Configuration builder tests
- `KeyDerivationTest` - Key derivation functionality tests
- `PasswordStrengthCheckerTest` - Password validation tests
- `KDFUsageExample` - Usage examples and integration tests

## References

- [RFC 8018 - PKCS #5: Password-Based Cryptography Specification](https://tools.ietf.org/html/rfc8018)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-132 - Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
