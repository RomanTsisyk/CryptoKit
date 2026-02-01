package io.github.romantsisyk.cryptolib.random

/**
 * Example usage class demonstrating the Secure Random module.
 * This class shows practical examples of how to use each component
 * in the random package for common cryptographic operations.
 */
object SecureRandomUsageExample {

    /**
     * Example 1: Generating random encryption keys
     */
    fun generateEncryptionKey(): ByteArray {
        // Generate a 256-bit (32-byte) encryption key
        return SecureRandomGenerator.generateBytes(32)
    }

    /**
     * Example 2: Generating an IV for AES-GCM encryption
     */
    fun generateEncryptionIV(): ByteArray {
        // For AES-GCM, 12 bytes (96 bits) is recommended
        return IVGenerator.generateIV()
    }

    /**
     * Example 3: Generating an IV for AES-CBC encryption
     */
    fun generateCBCIV(): ByteArray {
        // For AES-CBC, 16 bytes (128 bits) is required (matches block size)
        return IVGenerator.generateIV16()
    }

    /**
     * Example 4: Generating a salt for password hashing
     */
    fun generatePasswordSalt(): ByteArray {
        // Generate a 32-byte salt (256 bits) for password hashing
        return SaltGenerator.generateSalt()
    }

    /**
     * Example 5: Generating a salt and storing it as hex
     */
    fun generatePasswordSaltHex(): String {
        // Generate salt as hex string for easy storage
        return SaltGenerator.generateSaltHex()
    }

    /**
     * Example 6: Generating a secure random password
     */
    fun generateSecurePassword(): String {
        // Generate a 16-character password with all character types
        return RandomStringGenerator.generatePassword(
            length = 16,
            includeUppercase = true,
            includeLowercase = true,
            includeDigits = true,
            includeSpecial = true
        )
    }

    /**
     * Example 7: Generating a PIN code
     */
    fun generatePINCode(length: Int = 6): String {
        // Generate a numeric PIN code
        return RandomStringGenerator.generateNumeric(length)
    }

    /**
     * Example 8: Generating a verification code
     */
    fun generateVerificationCode(): String {
        // Generate a 6-character alphanumeric verification code
        return RandomStringGenerator.generateAlphanumeric(6)
    }

    /**
     * Example 9: Generating a session token
     */
    fun generateSessionToken(): String {
        // Generate a 32-byte token and encode as Base64
        return RandomStringGenerator.generateBase64(32)
    }

    /**
     * Example 10: Generating a random UUID for identifiers
     */
    fun generateUniqueIdentifier(): String {
        // Generate a UUID v4
        return SecureRandomGenerator.generateUUID()
    }

    /**
     * Example 11: Shuffling a list of items
     */
    fun <T> shuffleItems(items: List<T>): List<T> {
        // Create a mutable copy and shuffle it
        val mutableItems = items.toMutableList()
        return SecureRandomGenerator.shuffle(mutableItems)
    }

    /**
     * Example 12: Generating a random integer for OTP
     */
    fun generateOTP(digits: Int = 6): String {
        // Generate a random OTP with specified number of digits
        val min = Math.pow(10.0, (digits - 1).toDouble()).toInt()
        val max = Math.pow(10.0, digits.toDouble()).toInt() - 1
        val otp = SecureRandomGenerator.generateInt(min, max)
        return otp.toString()
    }

    /**
     * Example 13: Generating a temporary password
     */
    fun generateTemporaryPassword(): String {
        // Generate a 12-character password without special characters
        return RandomStringGenerator.generatePassword(
            length = 12,
            includeUppercase = true,
            includeLowercase = true,
            includeDigits = true,
            includeSpecial = false
        )
    }

    /**
     * Example 14: Generating a nonce for API requests
     */
    fun generateNonce(): ByteArray {
        // Generate a 12-byte nonce
        return IVGenerator.generateNonce(12)
    }

    /**
     * Example 15: Generating a hex-encoded challenge
     */
    fun generateChallenge(length: Int = 32): String {
        // Generate a hex string for challenge-response authentication
        return RandomStringGenerator.generateHex(length)
    }

    /**
     * Example 16: Generating random data for testing
     */
    fun generateTestData(size: Int): ByteArray {
        // Generate random bytes for testing purposes
        return SecureRandomGenerator.generateBytes(size)
    }

    /**
     * Example 17: Generating a random boolean for feature flags
     */
    fun shouldEnableFeature(): Boolean {
        // Randomly enable/disable a feature (50/50 chance)
        return SecureRandomGenerator.generateBoolean()
    }

    /**
     * Example 18: Selecting a random item from a list
     */
    fun <T> selectRandomItem(items: List<T>): T? {
        if (items.isEmpty()) return null
        val index = SecureRandomGenerator.generateInt(items.size)
        return items[index]
    }

    /**
     * Example 19: Generating multiple random values
     */
    fun generateMultipleKeys(count: Int, keySize: Int = 32): List<ByteArray> {
        return List(count) { SecureRandomGenerator.generateBytes(keySize) }
    }

    /**
     * Example 20: Complete encryption setup
     */
    data class EncryptionSetup(
        val key: ByteArray,
        val iv: ByteArray,
        val salt: ByteArray
    )

    fun generateEncryptionSetup(): EncryptionSetup {
        return EncryptionSetup(
            key = SecureRandomGenerator.generateBytes(32),  // 256-bit key
            iv = IVGenerator.generateIV(),                   // 12-byte IV for GCM
            salt = SaltGenerator.generateSalt()              // 32-byte salt
        )
    }
}
