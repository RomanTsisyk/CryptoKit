package io.github.romantsisyk.cryptolib.crypto.qr

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Comprehensive unit tests for QRUtils.
 * Tests encryption and decryption utility functions for QR code data.
 */
class QRUtilsTest {

    // Helper function to generate a test AES key
    private fun generateTestKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }

    // ==================== Tests for successful encryption ====================

    @Test
    fun `encryptData should encrypt simple text successfully`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Hello, World!"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertNotNull(iv)
        assertTrue(encryptedData.isNotEmpty())
        assertEquals(12, iv.size) // GCM standard IV size
    }

    @Test
    fun `encryptData should return valid Base64 encoded string`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Test Data"

        // Act
        val (encryptedData, _) = QRUtils.encryptData(originalData, key)

        // Assert - Should be valid Base64
        try {
            val decoded = Base64.getDecoder().decode(encryptedData)
            assertNotNull(decoded)
            assertTrue(decoded.isNotEmpty())
        } catch (e: IllegalArgumentException) {
            throw AssertionError("Encrypted data is not valid Base64: $encryptedData", e)
        }
    }

    @Test
    fun `encryptData should produce different ciphertext for same data with different IVs`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Same Data"

        // Act
        val (encrypted1, iv1) = QRUtils.encryptData(originalData, key)
        val (encrypted2, iv2) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotEquals(encrypted1, encrypted2) // Different ciphertext due to different IVs
        assertNotEquals(iv1.toList(), iv2.toList()) // Different IVs
    }

    @Test
    fun `encryptData should handle single character data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "X"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertTrue(encryptedData.isNotEmpty())
    }

    @Test
    fun `encryptData should handle long text data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "A".repeat(10000) // 10000 character string

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertTrue(encryptedData.isNotEmpty())
    }

    @Test
    fun `encryptData should handle special characters`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Special: !@#$%^&*()_+-={}[]|\\:\";<>?,./~`"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertTrue(encryptedData.isNotEmpty())
    }

    @Test
    fun `encryptData should handle unicode characters`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Unicode: \u4E2D\u6587 \uD83D\uDE00 \u00E9\u00F1"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertTrue(encryptedData.isNotEmpty())
    }

    @Test
    fun `encryptData should handle JSON formatted data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = """{"key":"value","number":123,"array":[1,2,3]}"""

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertTrue(encryptedData.isNotEmpty())
    }

    @Test
    fun `encryptData should handle newline and tab characters`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Line1\nLine2\tTab"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotNull(encryptedData)
        assertTrue(encryptedData.isNotEmpty())
    }

    // ==================== Tests for encryption error handling ====================

    @Test
    fun `encryptData should throw CryptoOperationException for empty data`() {
        // Arrange
        val key = generateTestKey()
        val emptyData = ""

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.encryptData(emptyData, key)
        }
        assertEquals("Encryption failed: data cannot be empty", exception.message)
    }

    // ==================== Tests for successful decryption ====================

    @Test
    fun `decryptData should decrypt data successfully`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Test Decryption"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `decryptData should handle single character data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Y"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `decryptData should handle long text data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "This is a longer test string that contains multiple words and sentences. " +
                "It should be encrypted and then decrypted correctly."
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `decryptData should handle special characters`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Special: !@#$%^&*()_+-={}[]|\\:\";<>?,./~`"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `decryptData should handle unicode characters`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Unicode: \u4E2D\u6587 \uD83D\uDE00"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `decryptData should handle JSON formatted data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = """{"key":"value","number":123,"bool":true}"""
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `decryptData should handle newline and tab characters`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Line1\nLine2\tTab"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    // ==================== Tests for decryption error handling ====================

    @Test
    fun `decryptData should throw CryptoOperationException for empty encrypted data`() {
        // Arrange
        val key = generateTestKey()
        val emptyEncryptedData = ""
        val iv = ByteArray(12)

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.decryptData(emptyEncryptedData, key, iv)
        }
        assertEquals("Decryption failed: encrypted data cannot be empty", exception.message)
    }

    @Test
    fun `decryptData should throw CryptoOperationException for invalid Base64 data`() {
        // Arrange
        val key = generateTestKey()
        val invalidBase64 = "!!!not-valid-base64@@@"
        val iv = ByteArray(12)

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.decryptData(invalidBase64, key, iv)
        }
        assertEquals("Decryption failed: invalid Base64 encoding", exception.message)
    }

    @Test
    fun `decryptData should throw CryptoOperationException for wrong key`() {
        // Arrange
        val correctKey = generateTestKey()
        val wrongKey = generateTestKey()
        val originalData = "Secret Data"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, correctKey)

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.decryptData(encryptedData, wrongKey, iv)
        }
        assertEquals("Decryption failed", exception.message)
    }

    @Test
    fun `decryptData should throw CryptoOperationException for wrong IV`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Secret Data"
        val (encryptedData, _) = QRUtils.encryptData(originalData, key)
        val wrongIv = ByteArray(12) { 0xFF.toByte() } // Different IV

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.decryptData(encryptedData, key, wrongIv)
        }
        assertEquals("Decryption failed", exception.message)
    }

    @Test
    fun `decryptData should throw CryptoOperationException for tampered encrypted data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Secret Data"
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Tamper with the encrypted data
        val tamperedData = encryptedData.dropLast(4) + "ABCD"

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.decryptData(tamperedData, key, iv)
        }
        assertEquals("Decryption failed", exception.message)
    }

    @Test
    fun `decryptData should throw CryptoOperationException for invalid IV size`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Secret Data"
        val (encryptedData, _) = QRUtils.encryptData(originalData, key)
        val invalidIv = ByteArray(8) // Wrong IV size (should be 12)

        // Act & Assert
        val exception = assertThrows(CryptoOperationException::class.java) {
            QRUtils.decryptData(encryptedData, key, invalidIv)
        }
        assertEquals("Decryption failed", exception.message)
    }

    // ==================== Integration tests ====================

    @Test
    fun `should successfully encrypt and decrypt round trip`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Round Trip Test"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `should handle multiple encrypt-decrypt cycles with same key`() {
        // Arrange
        val key = generateTestKey()
        val testData = listOf(
            "First Message",
            "Second Message",
            "Third Message"
        )

        // Act & Assert
        testData.forEach { data ->
            val (encrypted, iv) = QRUtils.encryptData(data, key)
            val decrypted = QRUtils.decryptData(encrypted, key, iv)
            assertEquals(data, decrypted)
        }
    }

    @Test
    fun `should produce different encrypted outputs for same data`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Identical Data"

        // Act
        val (encrypted1, iv1) = QRUtils.encryptData(originalData, key)
        val (encrypted2, iv2) = QRUtils.encryptData(originalData, key)

        // Assert
        assertNotEquals(encrypted1, encrypted2) // Different due to random IV
        assertEquals(originalData, QRUtils.decryptData(encrypted1, key, iv1))
        assertEquals(originalData, QRUtils.decryptData(encrypted2, key, iv2))
    }

    @Test
    fun `should handle complex JSON data encryption and decryption`() {
        // Arrange
        val key = generateTestKey()
        val complexJson = """
            {
                "user": {
                    "id": "12345",
                    "name": "John Doe",
                    "email": "john@example.com",
                    "preferences": {
                        "theme": "dark",
                        "notifications": true
                    }
                },
                "timestamp": "2024-01-15T10:30:00Z"
            }
        """.trimIndent()

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(complexJson, key)
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(complexJson, decryptedData)
    }

    @Test
    fun `should handle very long data encryption and decryption`() {
        // Arrange
        val key = generateTestKey()
        val longData = "Long Data ".repeat(1000) // 10000 characters

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(longData, key)
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(longData, decryptedData)
    }

    @Test
    fun `should maintain data integrity with binary-like data`() {
        // Arrange
        val key = generateTestKey()
        val binaryLikeData = (0..255).joinToString("") { it.toChar().toString() }

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(binaryLikeData, key)
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(binaryLikeData, decryptedData)
    }

    @Test
    fun `encryptData and decryptData should work with different key sizes`() {
        // Arrange
        val originalData = "Test with different key size"

        // Test with 128-bit key
        val keyGenerator128 = KeyGenerator.getInstance("AES")
        keyGenerator128.init(128)
        val key128 = keyGenerator128.generateKey()

        // Act & Assert
        val (encrypted, iv) = QRUtils.encryptData(originalData, key128)
        val decrypted = QRUtils.decryptData(encrypted, key128, iv)
        assertEquals(originalData, decrypted)
    }

    @Test
    fun `should preserve exact byte content through encryption and decryption`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Exact Content: \u0001\u0002\u0003\u0000"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)
        val decryptedData = QRUtils.decryptData(encryptedData, key, iv)

        // Assert
        assertEquals(originalData, decryptedData)
        assertArrayEquals(originalData.toByteArray(), decryptedData.toByteArray())
    }
}
