package io.github.romantsisyk.cryptolib.crypto.qr

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * QRUtils provides utility functions for encrypting and decrypting data for QR codes using AES/GCM encryption.
 * These functions help secure QR code data before transmission or storage.
 */
object QRUtils {
    private const val TRANSFORMATION = "AES/GCM/NoPadding" // AES GCM encryption mode
    private const val TAG_LENGTH_BIT = 128 // GCM authentication tag length in bits

    /**
     * Encrypts the given data using AES/GCM encryption.
     * The data is encoded into a Base64 string for easy transmission.
     * @param data The string data to encrypt.
     * @param key The SecretKey used for encryption.
     * @return A Pair containing the encrypted data (Base64) and the initialization vector (IV).
     * @throws CryptoOperationException if the encryption process fails or data is empty.
     */
    @JvmStatic
    fun encryptData(data: String, key: SecretKey): Pair<String, ByteArray> {
        if (data.isEmpty()) {
            throw CryptoOperationException("Encryption failed: data cannot be empty", null)
        }

        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv // Initialization vector used in AES GCM
            val encryptedBytes = cipher.doFinal(data.toByteArray()) // Perform encryption
            Base64.getEncoder().encodeToString(encryptedBytes) to iv // Return Base64 encoded encrypted data
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Encryption failed", e)
        }
    }

    /**
     * Decrypts the given encrypted data using AES/GCM decryption.
     * @param encryptedData The Base64 encoded encrypted data.
     * @param key The SecretKey used for decryption.
     * @param iv The initialization vector (IV) used during encryption.
     * @return The decrypted string data.
     * @throws CryptoOperationException if the decryption process fails or encryptedData is empty.
     */
    @JvmStatic
    fun decryptData(encryptedData: String, key: SecretKey, iv: ByteArray): String {
        if (encryptedData.isEmpty()) {
            throw CryptoOperationException("Decryption failed: encrypted data cannot be empty", null)
        }

        val decodedBytes = try {
            Base64.getDecoder().decode(encryptedData) // Decode Base64 encrypted data
        } catch (e: IllegalArgumentException) {
            throw CryptoOperationException("Decryption failed: invalid Base64 encoding", e)
        }

        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val gcmSpec = GCMParameterSpec(TAG_LENGTH_BIT, iv) // GCM spec for decryption
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec) // Initialize cipher with key and IV
            val decryptedBytes = cipher.doFinal(decodedBytes) // Perform decryption
            String(decryptedBytes) // Return decrypted string
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Decryption failed", e)
        }
    }
}
