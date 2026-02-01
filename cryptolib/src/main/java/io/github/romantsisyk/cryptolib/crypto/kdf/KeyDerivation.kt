package io.github.romantsisyk.cryptolib.crypto.kdf

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Object responsible for password-based key derivation operations.
 * Provides methods for deriving cryptographic keys from passwords using KDF algorithms.
 */
object KeyDerivation {

    /**
     * Default salt length in bytes (32 bytes = 256 bits).
     */
    private const val DEFAULT_SALT_LENGTH = 32

    /**
     * Shared SecureRandom instance for generating cryptographically secure random values.
     * Uses getInstanceStrong() to ensure the strongest available algorithm is used,
     * with a fallback to the default SecureRandom if strong instance is unavailable.
     */
    private val secureRandom: SecureRandom by lazy {
        try {
            SecureRandom.getInstanceStrong()
        } catch (e: Exception) {
            SecureRandom()
        }
    }

    /**
     * Derives a cryptographic key from a password using the specified configuration.
     *
     * @param password The password as a CharArray (use CharArray for security, can be zeroed out).
     * @param salt The salt value to use in the key derivation.
     * @param config The KDF configuration specifying algorithm, iterations, and key length.
     * @return The derived SecretKey.
     * @throws CryptoOperationException if key derivation fails.
     * @throws IllegalArgumentException if password or salt is empty.
     */
    @JvmStatic
    fun deriveKey(password: CharArray, salt: ByteArray, config: KDFConfig): SecretKey {
        require(password.isNotEmpty()) {
            "Password cannot be empty"
        }
        require(salt.isNotEmpty()) {
            "Salt cannot be empty"
        }
        require(salt.size >= 16) {
            "Salt should be at least 16 bytes for security, but was ${salt.size}"
        }

        return try {
            // Create a PBEKeySpec with the password, salt, iterations, and key length
            val spec = PBEKeySpec(password, salt, config.iterations, config.keyLength)

            // Get the SecretKeyFactory for the specified algorithm
            val factory = SecretKeyFactory.getInstance(config.algorithm.algorithmName)

            // Generate the key
            val derivedKey = factory.generateSecret(spec)

            // Clear the password from the spec for security
            spec.clearPassword()

            // Convert to a SecretKey suitable for use with AES
            SecretKeySpec(derivedKey.encoded, "AES")
        } catch (e: Exception) {
            throw CryptoOperationException("Key derivation failed", e)
        }
    }

    /**
     * Derives a cryptographic key from a password string using the specified configuration.
     * Note: For better security, prefer using the CharArray version which allows password clearing.
     *
     * @param password The password as a String.
     * @param salt The salt value to use in the key derivation.
     * @param config The KDF configuration specifying algorithm, iterations, and key length.
     * @return The derived SecretKey.
     * @throws CryptoOperationException if key derivation fails.
     * @throws IllegalArgumentException if password or salt is empty.
     */
    @JvmStatic
    fun deriveKey(password: String, salt: ByteArray, config: KDFConfig): SecretKey {
        require(password.isNotEmpty()) {
            "Password cannot be empty"
        }

        val passwordChars = password.toCharArray()
        try {
            return deriveKey(passwordChars, salt, config)
        } finally {
            // Clear the password array for security
            passwordChars.fill('\u0000')
        }
    }

    /**
     * Generates a cryptographically secure random salt.
     *
     * @param length The length of the salt in bytes (default is 32 bytes).
     * @return A randomly generated salt.
     * @throws IllegalArgumentException if length is less than 16 bytes.
     */
    @JvmStatic
    @JvmOverloads
    fun generateSalt(length: Int = DEFAULT_SALT_LENGTH): ByteArray {
        require(length >= 16) {
            "Salt length should be at least 16 bytes for security, but was $length"
        }

        val salt = ByteArray(length)
        secureRandom.nextBytes(salt)
        return salt
    }

    /**
     * Derives a key from a password and generates a new random salt.
     * This is a convenience method that combines salt generation and key derivation.
     *
     * @param password The password as a CharArray.
     * @param config The KDF configuration specifying algorithm, iterations, and key length.
     * @return A Pair containing the derived SecretKey and the generated salt.
     * @throws CryptoOperationException if key derivation fails.
     * @throws IllegalArgumentException if password is empty.
     */
    @JvmStatic
    fun deriveKeyWithNewSalt(password: CharArray, config: KDFConfig): Pair<SecretKey, ByteArray> {
        val salt = generateSalt()
        val key = deriveKey(password, salt, config)
        return Pair(key, salt)
    }

    /**
     * Derives a key from a password string and generates a new random salt.
     * This is a convenience method that combines salt generation and key derivation.
     * Note: For better security, prefer using the CharArray version which allows password clearing.
     *
     * @param password The password as a String.
     * @param config The KDF configuration specifying algorithm, iterations, and key length.
     * @return A Pair containing the derived SecretKey and the generated salt.
     * @throws CryptoOperationException if key derivation fails.
     * @throws IllegalArgumentException if password is empty.
     */
    @JvmStatic
    fun deriveKeyWithNewSalt(password: String, config: KDFConfig): Pair<SecretKey, ByteArray> {
        val salt = generateSalt()
        val key = deriveKey(password, salt, config)
        return Pair(key, salt)
    }
}
