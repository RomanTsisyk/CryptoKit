package io.github.romantsisyk.cryptolib.crypto.kdf

import org.junit.Test
import java.util.Arrays
import java.util.Base64

/**
 * Example usage of the Key Derivation Function (KDF) module.
 * This class demonstrates common use cases and best practices.
 */
class KDFUsageExample {

    @Test
    fun `example 1 - basic key derivation with default settings`() {
        // Use default configuration (PBKDF2-SHA256, 600,000 iterations, 256-bit key)
        val config = KDFConfig.getDefault()

        // Derive a key from a password
        val password = "MySecurePassword123!"
        val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)

        println("Derived key (Base64): ${Base64.getEncoder().encodeToString(key.encoded)}")
        println("Salt (Base64): ${Base64.getEncoder().encodeToString(salt)}")
        println("Key length: ${key.encoded.size} bytes")
        println("Salt length: ${salt.size} bytes")
    }

    @Test
    fun `example 2 - custom configuration for higher security`() {
        // Create a custom configuration with more iterations and SHA-512
        val config = KDFConfig.Builder()
            .iterations(200000)  // Double the default iterations
            .keyLength(512)      // 512-bit key instead of 256-bit
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)  // Use SHA-512 instead of SHA-256
            .build()

        val password = "MyVerySecurePassword!"
        val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)

        println("High-security key derived with 200,000 iterations")
        println("Key length: ${key.encoded.size} bytes (${key.encoded.size * 8} bits)")
    }

    @Test
    fun `example 3 - deriving key with existing salt for password verification`() {
        val password = "UserPassword123!"
        val config = KDFConfig.getDefault()

        // First time: derive key and store salt
        val (originalKey, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)
        println("Original key derived and salt stored")

        // Later: verify password by deriving key with stored salt
        val derivedKey = KeyDerivation.deriveKey(password, salt, config)

        // Compare keys to verify password
        val isPasswordCorrect = Arrays.equals(originalKey.encoded, derivedKey.encoded)
        println("Password verification: ${if (isPasswordCorrect) "SUCCESS" else "FAILED"}")
    }

    @Test
    fun `example 4 - using CharArray for secure password handling`() {
        // CharArray can be cleared from memory after use, unlike String
        val passwordChars = "SecurePassword123!".toCharArray()
        val config = KDFConfig.getDefault()

        try {
            val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(passwordChars, config)
            println("Key derived securely using CharArray")

            // Use the key...
        } finally {
            // Clear the password from memory
            passwordChars.fill('\u0000')
            println("Password cleared from memory")
        }
    }

    @Test
    fun `example 5 - password strength checking`() {
        val passwords = listOf(
            "password",           // Weak
            "Password1",          // Fair
            "MyP@ssw0rd123",     // Strong
            "MyV3ry\$tr0ng&C0mpl3xP@ssw0rd!"  // Very Strong
        )

        passwords.forEach { password ->
            val strength = PasswordStrengthChecker.checkStrength(password)
            val meetsRequirements = PasswordStrengthChecker.meetsMinimumRequirements(password)

            println("Password: $password")
            println("  Strength: $strength")
            println("  Meets requirements: $meetsRequirements")
            println()
        }
    }

    @Test
    fun `example 6 - password validation with custom requirements`() {
        val password = "UserPass1"

        // Check with default requirements
        val defaultErrors = PasswordStrengthChecker.validatePassword(password)
        println("Default validation errors: $defaultErrors")

        // Check with custom requirements (more lenient)
        val customErrors = PasswordStrengthChecker.validatePassword(
            password,
            minLength = 8,
            requireUppercase = true,
            requireDigit = true,
            requireSpecial = false  // Don't require special characters
        )
        println("Custom validation errors: $customErrors")
    }

    @Test
    fun `example 7 - complete user registration flow`() {
        val userPassword = "MySecurePassword123!"

        // Step 1: Check password strength
        val strength = PasswordStrengthChecker.checkStrength(userPassword)
        println("Password strength: $strength")

        // Step 2: Validate password meets requirements
        val errors = PasswordStrengthChecker.validatePassword(userPassword)
        if (errors.isNotEmpty()) {
            println("Password validation failed:")
            errors.forEach { println("  - $it") }
            return
        }
        println("Password validation passed")

        // Step 3: Derive key with new salt
        val config = KDFConfig.getDefault()
        val (derivedKey, salt) = KeyDerivation.deriveKeyWithNewSalt(userPassword, config)

        // Step 4: Store salt and use derived key
        // In a real application, you would:
        // - Store the salt in the database
        // - Use the derived key for encryption
        // - Never store the actual password
        println("User registered successfully")
        println("Salt to store (Base64): ${Base64.getEncoder().encodeToString(salt)}")
        println("Derived key for encryption: ${derivedKey.algorithm}")
    }

    @Test
    fun `example 8 - complete user login flow`() {
        // Simulate stored salt from registration
        val storedSalt = KeyDerivation.generateSalt()
        val correctPassword = "MySecurePassword123!"
        val config = KDFConfig.getDefault()

        // During registration: derive and store key
        val registrationKey = KeyDerivation.deriveKey(correctPassword, storedSalt, config)
        println("Registration: Key derived and stored")

        // During login: user enters password
        val loginPassword = "MySecurePassword123!"  // User input

        // Derive key with stored salt
        val loginKey = KeyDerivation.deriveKey(loginPassword, storedSalt, config)

        // Compare keys
        val loginSuccess = Arrays.equals(registrationKey.encoded, loginKey.encoded)
        println("Login attempt: ${if (loginSuccess) "SUCCESS" else "FAILED"}")
    }

    @Test
    fun `example 9 - generating cryptographic salt`() {
        // Generate default salt (32 bytes)
        val defaultSalt = KeyDerivation.generateSalt()
        println("Default salt size: ${defaultSalt.size} bytes")

        // Generate custom size salt (64 bytes)
        val largeSalt = KeyDerivation.generateSalt(64)
        println("Large salt size: ${largeSalt.size} bytes")

        // Each salt is unique
        val salt1 = KeyDerivation.generateSalt()
        val salt2 = KeyDerivation.generateSalt()
        val areUnique = !Arrays.equals(salt1, salt2)
        println("Salts are unique: $areUnique")
    }

    @Test
    fun `example 10 - different key lengths`() {
        val password = "TestPassword123!"
        val salt = KeyDerivation.generateSalt()

        // 128-bit key (minimum recommended)
        val config128 = KDFConfig.Builder().keyLength(128).build()
        val key128 = KeyDerivation.deriveKey(password, salt, config128)
        println("128-bit key size: ${key128.encoded.size} bytes")

        // 256-bit key (default, recommended for most uses)
        val config256 = KDFConfig.Builder().keyLength(256).build()
        val key256 = KeyDerivation.deriveKey(password, salt, config256)
        println("256-bit key size: ${key256.encoded.size} bytes")

        // 512-bit key (high security)
        val config512 = KDFConfig.Builder().keyLength(512).build()
        val key512 = KeyDerivation.deriveKey(password, salt, config512)
        println("512-bit key size: ${key512.encoded.size} bytes")
    }
}
