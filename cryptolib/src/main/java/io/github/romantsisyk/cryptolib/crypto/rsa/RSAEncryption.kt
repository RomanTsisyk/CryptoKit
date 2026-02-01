package io.github.romantsisyk.cryptolib.crypto.rsa

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Object responsible for RSA encryption and decryption operations using OAEP padding.
 * Provides methods for encrypting and decrypting data, as well as generating RSA key pairs.
 */
object RSAEncryption {

    private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private const val KEY_SIZE = 2048

    /**
     * Encrypts the provided plaintext data using RSA encryption with OAEP padding.
     *
     * @param plaintext The data to encrypt in ByteArray format.
     * @param publicKey The public RSA key used for encryption.
     * @return The encrypted data as a Base64-encoded string.
     * @throws CryptoOperationException if the plaintext is empty or the encryption process fails.
     */
    @JvmStatic
    fun encrypt(plaintext: ByteArray, publicKey: PublicKey): String {
        return try {
            // Input validation
            if (plaintext.isEmpty()) {
                throw IllegalArgumentException("Plaintext cannot be empty")
            }

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            val ciphertext = cipher.doFinal(plaintext)
            Base64.getEncoder().encodeToString(ciphertext)
        } catch (e: Exception) {
            throw CryptoOperationException("RSA Encryption failed: ${e.message}", e)
        }
    }

    /**
     * Decrypts the provided ciphertext using RSA decryption with OAEP padding.
     *
     * @param encryptedData The encrypted data as a Base64-encoded string.
     * @param privateKey The private RSA key used for decryption.
     * @return The decrypted data as a ByteArray.
     * @throws CryptoOperationException if the encrypted data is empty or the decryption process fails.
     */
    @JvmStatic
    fun decrypt(encryptedData: String, privateKey: PrivateKey): ByteArray {
        return try {
            // Input validation
            if (encryptedData.isEmpty()) {
                throw IllegalArgumentException("Encrypted data cannot be empty")
            }

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            val encryptedBytes = Base64.getDecoder().decode(encryptedData)
            cipher.doFinal(encryptedBytes)
        } catch (e: Exception) {
            throw CryptoOperationException("RSA Decryption failed: ${e.message}", e)
        }
    }

    /**
     * Generates a new RSA key pair (public and private keys).
     *
     * @return The generated RSA KeyPair.
     * @throws CryptoOperationException if the key pair generation fails.
     */
    @JvmStatic
    fun generateKeyPair(): KeyPair {
        return try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(KEY_SIZE)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            throw CryptoOperationException("RSA Key pair generation failed: ${e.message}", e)
        }
    }
}