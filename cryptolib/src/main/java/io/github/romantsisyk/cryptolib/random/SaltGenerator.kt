package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64

/**
 * Object responsible for generating cryptographically secure salts for password hashing
 * and key derivation. Provides methods for generating salts in various formats
 * (byte array, hexadecimal, Base64).
 */
object SaltGenerator {

    /**
     * Default salt length in bytes (32 bytes / 256 bits).
     * This is a recommended size for secure password hashing.
     */
    private const val DEFAULT_SALT_LENGTH = 32

    /**
     * Generates a cryptographically secure random salt as a byte array.
     * Salts are used in password hashing to ensure that identical passwords
     * produce different hash values.
     *
     * @param length The length of the salt in bytes. Default is 32 bytes.
     * @return A random salt byte array of the specified length.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    @JvmOverloads
    fun generateSalt(length: Int = DEFAULT_SALT_LENGTH): ByteArray {
        if (length <= 0) {
            throw CryptoOperationException("Salt generation failed: length must be positive")
        }

        return try {
            SecureRandomGenerator.generateBytes(length)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Salt generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random salt as a hexadecimal string.
     * The resulting string will be twice the length of the byte array (2 hex characters per byte).
     *
     * @param length The length of the salt in bytes. Default is 32 bytes (resulting in 64 hex characters).
     * @return A random salt as a hexadecimal string.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    @JvmOverloads
    fun generateSaltHex(length: Int = DEFAULT_SALT_LENGTH): String {
        if (length <= 0) {
            throw CryptoOperationException("Salt generation failed: length must be positive")
        }

        return try {
            val saltBytes = SecureRandomGenerator.generateBytes(length)
            bytesToHex(saltBytes)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Salt generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random salt as a Base64-encoded string.
     * Base64 encoding is more compact than hexadecimal (approximately 4/3 the length of the byte array).
     *
     * @param length The length of the salt in bytes. Default is 32 bytes.
     * @return A random salt as a Base64-encoded string.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    @JvmOverloads
    fun generateSaltBase64(length: Int = DEFAULT_SALT_LENGTH): String {
        if (length <= 0) {
            throw CryptoOperationException("Salt generation failed: length must be positive")
        }

        return try {
            val saltBytes = SecureRandomGenerator.generateBytes(length)
            Base64.getEncoder().encodeToString(saltBytes)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Salt generation failed", e)
        }
    }

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes The byte array to convert.
     * @return A hexadecimal string representation of the byte array.
     */
    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
            hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
        }
        return String(hexChars)
    }
}
