package io.github.romantsisyk.cryptolib

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object AESEncryption {

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12 // Recommended IV size for GCM
    private const val TAG_SIZE = 128

    /**
     * Encrypts plaintext using AES-GCM.
     */
    fun encrypt(plaintext: ByteArray, key: SecretKey): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)

        // Generate a random IV
        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(TAG_SIZE, iv)

        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val ciphertext = cipher.doFinal(plaintext)

        // Prepend IV to ciphertext
        val encrypted = iv + ciphertext

        // Return as Base64 string
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    /**
     * Decrypts ciphertext using AES-GCM.
     */
    fun decrypt(encryptedData: String, key: SecretKey): ByteArray {
        val encryptedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)

        // Extract IV and ciphertext
        val iv = encryptedBytes.copyOfRange(0, IV_SIZE)
        val ciphertext = encryptedBytes.copyOfRange(IV_SIZE, encryptedBytes.size)
        val spec = GCMParameterSpec(TAG_SIZE, iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return cipher.doFinal(ciphertext)
    }
}