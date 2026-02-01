package io.github.romantsisyk.cryptolib.crypto.aes

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AESEncryptionTest {

    @Test
    fun `test AES encryption and decryption`() {
        val key = AESEncryption.generateKey()
        val originalText = "Hello, World!".toByteArray()
        val encryptedText = AESEncryption.encrypt(originalText, key)
        val decryptedText = AESEncryption.decrypt(encryptedText, key)

        assertArrayEquals(originalText, decryptedText)
    }

    @Test
    fun `test AES decryption with invalid key`() {
        val key = AESEncryption.generateKey()
        val invalidKey = AESEncryption.generateKey()
        val originalText = "Test".toByteArray()
        val encryptedText = AESEncryption.encrypt(originalText, key)

        assertThrows(CryptoOperationException::class.java) {
            AESEncryption.decrypt(encryptedText, invalidKey)
        }
    }

    @Test
    fun `test encrypting empty byte array throws CryptoOperationException`() {
        val key = AESEncryption.generateKey()
        val emptyData = ByteArray(0)

        assertThrows(CryptoOperationException::class.java) {
            AESEncryption.encrypt(emptyData, key)
        }
    }

    @Test
    fun `test multiple encryptions of same data produce different ciphertexts`() {
        val key = AESEncryption.generateKey()
        val originalText = "Same data for IV uniqueness test".toByteArray()

        val encryptedText1 = AESEncryption.encrypt(originalText, key)
        val encryptedText2 = AESEncryption.encrypt(originalText, key)

        // Due to random IV generation, each encryption should produce different ciphertext
        assertNotEquals(encryptedText1, encryptedText2)

        // Both should still decrypt to the same original text
        assertArrayEquals(originalText, AESEncryption.decrypt(encryptedText1, key))
        assertArrayEquals(originalText, AESEncryption.decrypt(encryptedText2, key))
    }

    @Test
    fun `test decrypting invalid Base64 throws CryptoOperationException`() {
        val key = AESEncryption.generateKey()
        val invalidBase64 = "!!!not-valid-base64@@@"

        assertThrows(CryptoOperationException::class.java) {
            AESEncryption.decrypt(invalidBase64, key)
        }
    }

    @Test
    fun `test decrypting data shorter than IV_SIZE throws CryptoOperationException`() {
        val key = AESEncryption.generateKey()
        // IV_SIZE is 12 bytes, so we create data that is shorter when decoded
        // Base64 encoding of 8 bytes (less than 12)
        val shortData = java.util.Base64.getEncoder().encodeToString(ByteArray(8))

        assertThrows(CryptoOperationException::class.java) {
            AESEncryption.decrypt(shortData, key)
        }
    }
}
