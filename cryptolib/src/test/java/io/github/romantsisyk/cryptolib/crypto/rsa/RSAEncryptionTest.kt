package io.github.romantsisyk.cryptolib.crypto.rsa

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator

class RSAEncryptionTest {

    @Test
    fun `test RSA encryption and decryption`() {
        val keyPair = RSAEncryption.generateKeyPair()
        val originalText = "Secure Message".toByteArray()
        val encryptedText = RSAEncryption.encrypt(originalText, keyPair.public)
        val decryptedText = RSAEncryption.decrypt(encryptedText, keyPair.private)

        assertArrayEquals(originalText, decryptedText)
    }

    @Test(expected = CryptoOperationException::class)
    fun `test RSA decryption with invalid key`() {
        val keyPair = RSAEncryption.generateKeyPair()
        val invalidKeyPair = RSAEncryption.generateKeyPair()
        val originalText = "Secure Data".toByteArray()
        val encryptedText = RSAEncryption.encrypt(originalText, keyPair.public)

        RSAEncryption.decrypt(encryptedText, invalidKeyPair.private)
    }

    @Test(expected = CryptoOperationException::class)
    fun `test encrypting empty data throws CryptoOperationException`() {
        val keyPair = RSAEncryption.generateKeyPair()
        val emptyData = byteArrayOf()

        RSAEncryption.encrypt(emptyData, keyPair.public)
    }

    @Test(expected = CryptoOperationException::class)
    fun `test decrypting empty data throws CryptoOperationException`() {
        val keyPair = RSAEncryption.generateKeyPair()
        val emptyEncryptedData = ""

        RSAEncryption.decrypt(emptyEncryptedData, keyPair.private)
    }

    @Test(expected = CryptoOperationException::class)
    fun `test decrypting invalid Base64 throws CryptoOperationException`() {
        val keyPair = RSAEncryption.generateKeyPair()
        val invalidBase64 = "!!!not-valid-base64@@@"

        RSAEncryption.decrypt(invalidBase64, keyPair.private)
    }

    @Test(expected = CryptoOperationException::class)
    fun `test encrypting with wrong key type fails appropriately`() {
        // Generate a DSA key pair instead of RSA
        val dsaKeyPairGenerator = KeyPairGenerator.getInstance("DSA")
        dsaKeyPairGenerator.initialize(2048)
        val dsaKeyPair = dsaKeyPairGenerator.generateKeyPair()

        val plaintext = "Test message".toByteArray()

        // Attempt to encrypt with a DSA public key (wrong key type)
        RSAEncryption.encrypt(plaintext, dsaKeyPair.public)
    }
}