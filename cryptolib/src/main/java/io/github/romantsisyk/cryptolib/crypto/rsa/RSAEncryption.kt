package io.github.romantsisyk.cryptolib.crypto.rsa

import java.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import java.security.PrivateKey
import java.security.PublicKey

object RSAEncryption {

    private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private const val KEY_SIZE = 2048

    /**
     * Encrypts the provided plaintext data using RSA encryption with OAEP padding.
     * @param plaintext The data to encrypt.
     * @param publicKey The public RSA key used for encryption.
     * @return The encrypted data in base64 format.
     */
    fun encrypt(plaintext: ByteArray, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val ciphertext = cipher.doFinal(plaintext)
        return Base64.getEncoder().encodeToString(ciphertext)
    }

    /**
     * Decrypts the provided ciphertext using RSA decryption with OAEP padding.
     * @param encryptedData The encrypted data in base64 format.
     * @param privateKey The private RSA key used for decryption.
     * @return The decrypted data as a byte array.
     */
    fun decrypt(encryptedData: String, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val encryptedBytes = Base64.getDecoder().decode(encryptedData)
        return cipher.doFinal(encryptedBytes)
    }

    /**
     * Generates a new RSA key pair (public and private keys).
     * @return The generated RSA key pair.
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(KEY_SIZE)
        return keyPairGenerator.generateKeyPair()
    }
}