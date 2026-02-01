package io.github.romantsisyk.cryptolib.crypto.kdf

import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Arrays

/**
 * Integration tests demonstrating how the KDF module works with other CryptoKit components.
 */
class KDFIntegrationTest {

    @Test
    fun `test KDF integration with AES encryption`() {
        // User's password
        val password = "MySecurePassword123!"

        // Step 1: Check password strength
        val strength = PasswordStrengthChecker.checkStrength(password)
        assertEquals(PasswordStrength.STRONG, strength)

        // Step 2: Validate password requirements
        val meetsRequirements = PasswordStrengthChecker.meetsMinimumRequirements(password)
        assertEquals(true, meetsRequirements)

        // Step 3: Derive encryption key from password
        val kdfConfig = KDFConfig.getDefault()
        val (encryptionKey, salt) = KeyDerivation.deriveKeyWithNewSalt(password, kdfConfig)

        // Step 4: Use derived key for AES encryption
        val plaintext = "Sensitive data to encrypt".toByteArray()
        val encrypted = AESEncryption.encrypt(plaintext, encryptionKey)

        // Step 5: Decrypt using the same derived key
        val decrypted = AESEncryption.decrypt(encrypted, encryptionKey)
        assertArrayEquals(plaintext, decrypted)

        // Step 6: Verify we can reproduce the key with the stored salt
        val reproducedKey = KeyDerivation.deriveKey(password, salt, kdfConfig)
        val decryptedWithReproducedKey = AESEncryption.decrypt(encrypted, reproducedKey)
        assertArrayEquals(plaintext, decryptedWithReproducedKey)
    }

    @Test
    fun `test complete user authentication flow with encryption`() {
        val userPassword = "UserPassword123!"
        val sensitiveData = "User's confidential information".toByteArray()

        // === REGISTRATION FLOW ===

        // 1. Validate password
        val validationErrors = PasswordStrengthChecker.validatePassword(userPassword)
        assertEquals(emptyList<String>(), validationErrors)

        // 2. Derive key and generate salt
        val config = KDFConfig.Builder()
            .iterations(150000)
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)
            .build()
        val (registrationKey, registrationSalt) = KeyDerivation.deriveKeyWithNewSalt(userPassword, config)

        // 3. Encrypt user data with derived key
        val encryptedData = AESEncryption.encrypt(sensitiveData, registrationKey)

        // 4. In real app: store salt and encrypted data in database
        // (Don't store the password or key!)

        // === LOGIN FLOW ===

        // 5. User enters password at login
        val loginPassword = "UserPassword123!"

        // 6. Derive key using stored salt
        val loginKey = KeyDerivation.deriveKey(loginPassword, registrationSalt, config)

        // 7. Verify password by comparing keys
        val isPasswordCorrect = Arrays.equals(registrationKey.encoded, loginKey.encoded)
        assertEquals(true, isPasswordCorrect)

        // 8. Decrypt user data if password is correct
        if (isPasswordCorrect) {
            val decryptedData = AESEncryption.decrypt(encryptedData, loginKey)
            assertArrayEquals(sensitiveData, decryptedData)
        }
    }

    @Test
    fun `test password change flow`() {
        val oldPassword = "OldPassword123!"
        val newPassword = "NewSecurePassword456!"
        val userData = "User's encrypted data".toByteArray()

        val config = KDFConfig.getDefault()

        // Step 1: Current state - data encrypted with old password
        val (oldKey, oldSalt) = KeyDerivation.deriveKeyWithNewSalt(oldPassword, config)
        val encryptedWithOldPassword = AESEncryption.encrypt(userData, oldKey)

        // Step 2: User requests password change
        // Validate new password
        val validationErrors = PasswordStrengthChecker.validatePassword(newPassword)
        assertEquals(emptyList<String>(), validationErrors)

        // Step 3: Verify old password
        val enteredOldPassword = "OldPassword123!"
        val verificationKey = KeyDerivation.deriveKey(enteredOldPassword, oldSalt, config)
        val isOldPasswordCorrect = Arrays.equals(oldKey.encoded, verificationKey.encoded)
        assertEquals(true, isOldPasswordCorrect)

        // Step 4: Decrypt with old key
        val decryptedData = AESEncryption.decrypt(encryptedWithOldPassword, oldKey)

        // Step 5: Derive new key from new password
        val (newKey, newSalt) = KeyDerivation.deriveKeyWithNewSalt(newPassword, config)

        // Step 6: Re-encrypt with new key
        val encryptedWithNewPassword = AESEncryption.encrypt(decryptedData, newKey)

        // Step 7: Verify we can decrypt with new password
        val finalDecrypted = AESEncryption.decrypt(encryptedWithNewPassword, newKey)
        assertArrayEquals(userData, finalDecrypted)

        // Step 8: Store new salt and encrypted data
        // (In real app: update database with newSalt and encryptedWithNewPassword)
    }

    @Test
    fun `test different key lengths with AES encryption`() {
        val password = "TestPassword123!"
        val plaintext = "Test data".toByteArray()

        // Test with 256-bit key (default)
        val config256 = KDFConfig.Builder().keyLength(256).build()
        val (key256, salt256) = KeyDerivation.deriveKeyWithNewSalt(password, config256)
        val encrypted256 = AESEncryption.encrypt(plaintext, key256)
        val decrypted256 = AESEncryption.decrypt(encrypted256, key256)
        assertArrayEquals(plaintext, decrypted256)
        assertEquals(32, key256.encoded.size) // 256 bits = 32 bytes

        // Note: AES typically uses 128 or 256-bit keys
        // The KDF can generate keys of different lengths,
        // but they will be used as AES keys
    }

    @Test
    fun `test high security configuration`() {
        val password = "HighSecurityPassword123!"
        val sensitiveData = "Top secret information".toByteArray()

        // High security configuration
        val highSecConfig = KDFConfig.Builder()
            .iterations(250000)  // Very high iteration count
            .keyLength(512)      // Large key size
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)  // SHA-512
            .build()

        // Derive key
        val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, highSecConfig)

        // For AES, we'll use the first 256 bits of the derived key
        // In practice, you might use different portions for different purposes
        // (e.g., encryption key, MAC key)
        val aesKey = javax.crypto.spec.SecretKeySpec(
            key.encoded.copyOf(32),  // Use first 32 bytes (256 bits)
            "AES"
        )

        // Encrypt and decrypt
        val encrypted = AESEncryption.encrypt(sensitiveData, aesKey)
        val decrypted = AESEncryption.decrypt(encrypted, aesKey)
        assertArrayEquals(sensitiveData, decrypted)
    }

    @Test
    fun `test multiple user accounts with different passwords`() {
        val config = KDFConfig.getDefault()

        // User 1
        val user1Password = "User1Password!"
        val user1Data = "User 1 data".toByteArray()
        val (user1Key, user1Salt) = KeyDerivation.deriveKeyWithNewSalt(user1Password, config)
        val user1Encrypted = AESEncryption.encrypt(user1Data, user1Key)

        // User 2
        val user2Password = "User2Password!"
        val user2Data = "User 2 data".toByteArray()
        val (user2Key, user2Salt) = KeyDerivation.deriveKeyWithNewSalt(user2Password, config)
        val user2Encrypted = AESEncryption.encrypt(user2Data, user2Key)

        // Verify each user can only decrypt their own data
        val user1Decrypted = AESEncryption.decrypt(user1Encrypted, user1Key)
        assertArrayEquals(user1Data, user1Decrypted)

        val user2Decrypted = AESEncryption.decrypt(user2Encrypted, user2Key)
        assertArrayEquals(user2Data, user2Decrypted)

        // Verify keys are different
        assertEquals(false, Arrays.equals(user1Key.encoded, user2Key.encoded))

        // Verify salts are different
        assertEquals(false, Arrays.equals(user1Salt, user2Salt))
    }

    @Test
    fun `test secure password handling with CharArray`() {
        // Best practice: use CharArray for passwords so they can be cleared
        val passwordChars = "SecurePassword123!".toCharArray()
        val data = "Sensitive information".toByteArray()

        try {
            val config = KDFConfig.getDefault()
            val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(passwordChars, config)

            val encrypted = AESEncryption.encrypt(data, key)
            val decrypted = AESEncryption.decrypt(encrypted, key)

            assertArrayEquals(data, decrypted)
        } finally {
            // Clear password from memory
            passwordChars.fill('\u0000')

            // Verify password is cleared
            assertEquals('\u0000', passwordChars[0])
        }
    }

    @Test
    fun `test password strength affects security posture`() {
        val weakPassword = "pass"
        val strongPassword = "MyV3ry$tr0ng&P@ssw0rd123!"

        // Check strengths
        val weakStrength = PasswordStrengthChecker.checkStrength(weakPassword)
        val strongStrength = PasswordStrengthChecker.checkStrength(strongPassword)

        assertEquals(PasswordStrength.WEAK, weakStrength)
        assertEquals(PasswordStrength.VERY_STRONG, strongStrength)

        // Both can technically be used for key derivation,
        // but weak passwords are vulnerable to brute force attacks
        val config = KDFConfig.getDefault()

        // Weak password (don't use in production!)
        // This would pass KDF but is not secure
        val (weakKey, weakSalt) = KeyDerivation.deriveKeyWithNewSalt(weakPassword, config)
        assertEquals(32, weakKey.encoded.size)

        // Strong password (recommended)
        val (strongKey, strongSalt) = KeyDerivation.deriveKeyWithNewSalt(strongPassword, config)
        assertEquals(32, strongKey.encoded.size)

        // Both produce valid keys, but the strong password provides better security
        // against brute force attacks even with the same KDF configuration
    }
}
