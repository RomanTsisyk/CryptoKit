package io.github.romantsisyk.cryptolib.crypto.aes

import java.util.Base64
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Object responsible for AES encryption and decryption operations using the AES-GCM algorithm.
 * Provides methods for encrypting and decrypting data, as well as generating AES keys.
 */
object AESEncryption {

    private const val TRANSFORMATION = "AES/GCM/NoPadding" // AES-GCM algorithm transformation
    private const val IV_SIZE = 12 // Recommended IV size for GCM mode
    private const val TAG_SIZE = 128 // Tag size for GCM mode (in bits)
    private const val KEY_SIZE = 256 // Key size (in bits)

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
     * Encrypts the provided plaintext using AES-GCM encryption.
     *
     * @param plaintext The data to be encrypted in ByteArray format.
     * @param key The AES SecretKey used for encryption.
     * @return A Base64-encoded string containing the IV and the ciphertext.
     * @throws CryptoOperationException if the encryption process fails.
     */
    @JvmStatic
    fun encrypt(plaintext: ByteArray, key: SecretKey): String {
        if (plaintext.isEmpty()) {
            throw CryptoOperationException("Encryption failed: plaintext cannot be empty")
        }

        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)

            // Generate a random IV (Initialization Vector) using the shared SecureRandom instance
            val iv = ByteArray(IV_SIZE)
            secureRandom.nextBytes(iv)
            val spec = GCMParameterSpec(TAG_SIZE, iv)

            // Initialize the cipher for encryption and perform the encryption
            cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            val ciphertext = cipher.doFinal(plaintext)

            // Prepend IV to ciphertext for later use in decryption
            val encrypted = iv + ciphertext

            // Return the encrypted data as a Base64 string
            Base64.getEncoder().encodeToString(encrypted)
        } catch (e: Exception) {
            throw CryptoOperationException("Encryption", e)
        }
    }

    /**
     * Decrypts the provided Base64-encoded encrypted data using AES-GCM decryption.
     *
     * @param encryptedData A Base64-encoded string containing the IV and the ciphertext.
     * @param key The AES SecretKey used for decryption.
     * @return The decrypted data as a ByteArray.
     * @throws CryptoOperationException if the decryption process fails.
     */
    @JvmStatic
    fun decrypt(encryptedData: String, key: SecretKey): ByteArray {
        if (encryptedData.isEmpty()) {
            throw CryptoOperationException("Decryption failed: encrypted data cannot be empty")
        }

        val encryptedBytes = try {
            Base64.getDecoder().decode(encryptedData)
        } catch (e: IllegalArgumentException) {
            throw CryptoOperationException("Decryption failed: invalid Base64 encoding", e)
        }

        if (encryptedBytes.size < IV_SIZE) {
            throw CryptoOperationException(
                "Decryption failed: encrypted data is too short (minimum $IV_SIZE bytes required for IV)"
            )
        }

        return try {
            // Extract IV and ciphertext from the encrypted data
            val iv = encryptedBytes.copyOfRange(0, IV_SIZE)
            val ciphertext = encryptedBytes.copyOfRange(IV_SIZE, encryptedBytes.size)
            val spec = GCMParameterSpec(TAG_SIZE, iv)

            // Initialize the cipher for decryption and perform the decryption
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            cipher.doFinal(ciphertext)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Decryption", e)
        }
    }

    /**
     * Generates a new AES key with the specified key size.
     *
     * @return A newly generated AES SecretKey.
     */
    @JvmStatic
    fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(KEY_SIZE)
        return keyGenerator.generateKey()
    }
}
