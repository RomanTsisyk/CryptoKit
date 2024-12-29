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
     * Encrypts the provided plaintext using AES-GCM encryption.
     *
     * @param plaintext The data to be encrypted in ByteArray format.
     * @param key The AES SecretKey used for encryption.
     * @return A Base64-encoded string containing the IV and the ciphertext.
     * @throws CryptoOperationException if the encryption process fails.
     */
    fun encrypt(plaintext: ByteArray, key: SecretKey): String {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)

            // Generate a random IV (Initialization Vector)
            val iv = ByteArray(IV_SIZE)
            SecureRandom().nextBytes(iv)
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
    fun decrypt(encryptedData: String, key: SecretKey): ByteArray {
        return try {
            val encryptedBytes = Base64.getDecoder().decode(encryptedData)

            // Extract IV and ciphertext from the encrypted data
            val iv = encryptedBytes.copyOfRange(0, IV_SIZE)
            val ciphertext = encryptedBytes.copyOfRange(IV_SIZE, encryptedBytes.size)
            val spec = GCMParameterSpec(TAG_SIZE, iv)

            // Initialize the cipher for decryption and perform the decryption
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            throw CryptoOperationException("Decryption", e)
        }
    }

    /**
     * Generates a new AES key with the specified key size.
     *
     * @return A newly generated AES SecretKey.
     */
    fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(KEY_SIZE)
        return keyGenerator.generateKey()
    }
}
