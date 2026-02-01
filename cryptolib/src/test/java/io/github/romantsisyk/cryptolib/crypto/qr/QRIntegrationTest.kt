package io.github.romantsisyk.cryptolib.crypto.qr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import javax.crypto.KeyGenerator

/**
 * Integration tests for QR code functionality.
 * Tests the complete workflow of generating, scanning, encrypting, and decrypting QR codes.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30], manifest = Config.NONE)
class QRIntegrationTest {

    private fun generateTestKey() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    // ==================== Basic QR Generation and Scanning ====================

    @Test
    fun `should generate and scan QR code successfully`() {
        // Arrange
        val testData = "Integration Test Data"

        // Act
        val qrBitmap = QRCodeGenerator.generateQRCode(testData)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(testData, scannedData)
    }

    @Test
    fun `should handle complete QR workflow with different data types`() {
        // Arrange
        val testCases = listOf(
            "Simple text",
            "123456789",
            "https://example.com/path?query=value",
            """{"key":"value","number":123}""",
            "Special: !@#$%^&*()"
        )

        // Act & Assert
        testCases.forEach { testData ->
            val qrBitmap = QRCodeGenerator.generateQRCode(testData, 300, 300)
            val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
            assertEquals(testData, scannedData)
        }
    }

    @Test
    fun `should handle QR codes of different sizes`() {
        // Arrange
        val testData = "Size Test Data"
        val sizes = listOf(100, 200, 300, 500, 1000)

        // Act & Assert
        sizes.forEach { size ->
            val qrBitmap = QRCodeGenerator.generateQRCode(testData, size, size)
            val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
            assertEquals(testData, scannedData)
        }
    }

    // ==================== Encrypted QR Code Workflow ====================

    @Test
    fun `should encrypt data, embed in QR, scan and decrypt successfully`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Secret Message"

        // Act - Encrypt
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)

        // Act - Generate QR with encrypted data
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData, 400, 400)

        // Act - Scan QR
        val scannedEncryptedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Act - Decrypt
        val decryptedData = QRUtils.decryptData(scannedEncryptedData, key, iv)

        // Assert
        assertEquals(encryptedData, scannedEncryptedData)
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `should handle encrypted QR workflow with complex JSON data`() {
        // Arrange
        val key = generateTestKey()
        val complexJson = """
            {
                "transaction": "0xABC123DEF456",
                "amount": 1234.56,
                "timestamp": "2024-01-15T10:30:00Z",
                "metadata": {
                    "type": "payment",
                    "verified": true
                }
            }
        """.trimIndent()

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(complexJson, key)
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData, 500, 500)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
        val decryptedData = QRUtils.decryptData(scannedData, key, iv)

        // Assert
        assertEquals(complexJson, decryptedData)
    }

    @Test
    fun `should handle encrypted QR workflow with long text`() {
        // Arrange
        val key = generateTestKey()
        val longText = "This is a long test message. ".repeat(50) // 1500 characters

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(longText, key)
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData, 800, 800)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
        val decryptedData = QRUtils.decryptData(scannedData, key, iv)

        // Assert
        assertEquals(longText, decryptedData)
    }

    @Test
    fun `should handle encrypted QR workflow with unicode characters`() {
        // Arrange
        val key = generateTestKey()
        val unicodeData = "Hello \u4E2D\u6587 World \uD83D\uDE00 Test \u00E9\u00F1"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(unicodeData, key)
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData, 400, 400)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
        val decryptedData = QRUtils.decryptData(scannedData, key, iv)

        // Assert
        assertEquals(unicodeData, decryptedData)
    }

    // ==================== Multiple QR Codes ====================

    @Test
    fun `should handle multiple different encrypted QR codes`() {
        // Arrange
        val key = generateTestKey()
        val messages = listOf(
            "First Secret",
            "Second Secret",
            "Third Secret"
        )

        // Act & Assert
        messages.forEach { message ->
            val (encryptedData, iv) = QRUtils.encryptData(message, key)
            val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData)
            val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
            val decryptedData = QRUtils.decryptData(scannedData, key, iv)

            assertEquals(message, decryptedData)
        }
    }

    @Test
    fun `should produce different QR codes for same data due to encryption IV`() {
        // Arrange
        val key = generateTestKey()
        val testData = "Same Data"

        // Act
        val (encrypted1, iv1) = QRUtils.encryptData(testData, key)
        val (encrypted2, iv2) = QRUtils.encryptData(testData, key)

        val qr1 = QRCodeGenerator.generateQRCode(encrypted1)
        val qr2 = QRCodeGenerator.generateQRCode(encrypted2)

        // Assert - Different encrypted data and QR codes
        assertNotEquals(encrypted1, encrypted2)

        // But both should decrypt to the same original data
        val scanned1 = QRCodeScanner.decodeQRCode(qr1)
        val scanned2 = QRCodeScanner.decodeQRCode(qr2)

        assertEquals(testData, QRUtils.decryptData(scanned1, key, iv1))
        assertEquals(testData, QRUtils.decryptData(scanned2, key, iv2))
    }

    // ==================== Data Integrity Tests ====================

    @Test
    fun `should preserve data integrity through complete workflow`() {
        // Arrange
        val key = generateTestKey()
        val originalData = "Data Integrity Test: !@#$%^&*()_+-={}[]|\\:\";<>?,./~`"

        // Act - Complete workflow
        val (encryptedData, iv) = QRUtils.encryptData(originalData, key)
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData, 400, 400)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
        val decryptedData = QRUtils.decryptData(scannedData, key, iv)

        // Assert - Verify data at each step
        assertNotNull(encryptedData)
        assertNotNull(qrBitmap)
        assertNotNull(scannedData)
        assertEquals(encryptedData, scannedData)
        assertEquals(originalData, decryptedData)
    }

    @Test
    fun `should handle workflow with Base64 encoded data`() {
        // Arrange
        val key = generateTestKey()
        val base64Data = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg=="

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(base64Data, key)
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
        val decryptedData = QRUtils.decryptData(scannedData, key, iv)

        // Assert
        assertEquals(base64Data, decryptedData)
    }

    @Test
    fun `should handle workflow with newlines and special whitespace`() {
        // Arrange
        val key = generateTestKey()
        val dataWithWhitespace = "Line1\nLine2\n\tTabbed\r\nCarriageReturn"

        // Act
        val (encryptedData, iv) = QRUtils.encryptData(dataWithWhitespace, key)
        val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData)
        val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
        val decryptedData = QRUtils.decryptData(scannedData, key, iv)

        // Assert
        assertEquals(dataWithWhitespace, decryptedData)
    }

    // ==================== Performance and Stress Tests ====================

    @Test
    fun `should handle multiple sequential QR operations`() {
        // Arrange
        val key = generateTestKey()
        val iterations = 10

        // Act & Assert
        repeat(iterations) { i ->
            val testData = "Iteration $i data"
            val (encryptedData, iv) = QRUtils.encryptData(testData, key)
            val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData)
            val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
            val decryptedData = QRUtils.decryptData(scannedData, key, iv)

            assertEquals(testData, decryptedData)
        }
    }

    @Test
    fun `should handle varying QR sizes with encrypted data`() {
        // Arrange
        val key = generateTestKey()
        val testData = "Variable Size Test"
        val (encryptedData, iv) = QRUtils.encryptData(testData, key)

        // Act & Assert
        listOf(150, 250, 350, 450, 550).forEach { size ->
            val qrBitmap = QRCodeGenerator.generateQRCode(encryptedData, size, size)
            val scannedData = QRCodeScanner.decodeQRCode(qrBitmap)
            val decryptedData = QRUtils.decryptData(scannedData, key, iv)

            assertEquals(testData, decryptedData)
        }
    }

    // ==================== Real-World Scenarios ====================

    @Test
    fun `should handle payment QR code scenario`() {
        // Arrange
        val key = generateTestKey()
        val paymentData = """
            {
                "type": "payment",
                "amount": 99.99,
                "currency": "USD",
                "recipient": "user@example.com",
                "reference": "INV-2024-001",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        """.trimIndent()

        // Act - Simulate sending payment via QR
        val (encryptedPayment, iv) = QRUtils.encryptData(paymentData, key)
        val paymentQR = QRCodeGenerator.generateQRCode(encryptedPayment, 400, 400)

        // Simulate scanning payment QR
        val scannedPayment = QRCodeScanner.decodeQRCode(paymentQR)
        val decryptedPayment = QRUtils.decryptData(scannedPayment, key, iv)

        // Assert
        assertEquals(paymentData, decryptedPayment)
    }

    @Test
    fun `should handle authentication token QR code scenario`() {
        // Arrange
        val key = generateTestKey()
        val authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"

        // Act - Simulate sharing auth token via QR
        val (encryptedToken, iv) = QRUtils.encryptData(authToken, key)
        val tokenQR = QRCodeGenerator.generateQRCode(encryptedToken, 350, 350)

        // Simulate scanning auth token QR
        val scannedToken = QRCodeScanner.decodeQRCode(tokenQR)
        val decryptedToken = QRUtils.decryptData(scannedToken, key, iv)

        // Assert
        assertEquals(authToken, decryptedToken)
    }

    @Test
    fun `should handle contact information QR code scenario`() {
        // Arrange
        val key = generateTestKey()
        val contactVCard = """
            BEGIN:VCARD
            VERSION:3.0
            FN:John Doe
            TEL:+1-555-1234
            EMAIL:john.doe@example.com
            ORG:Example Corp
            END:VCARD
        """.trimIndent()

        // Act
        val (encryptedContact, iv) = QRUtils.encryptData(contactVCard, key)
        val contactQR = QRCodeGenerator.generateQRCode(encryptedContact, 400, 400)
        val scannedContact = QRCodeScanner.decodeQRCode(contactQR)
        val decryptedContact = QRUtils.decryptData(scannedContact, key, iv)

        // Assert
        assertEquals(contactVCard, decryptedContact)
    }

    @Test
    fun `should handle WiFi credentials QR code scenario`() {
        // Arrange
        val key = generateTestKey()
        val wifiConfig = """
            {
                "ssid": "MySecureNetwork",
                "password": "SuperSecretP@ssw0rd!",
                "encryption": "WPA2",
                "hidden": false
            }
        """.trimIndent()

        // Act
        val (encryptedWifi, iv) = QRUtils.encryptData(wifiConfig, key)
        val wifiQR = QRCodeGenerator.generateQRCode(encryptedWifi, 350, 350)
        val scannedWifi = QRCodeScanner.decodeQRCode(wifiQR)
        val decryptedWifi = QRUtils.decryptData(scannedWifi, key, iv)

        // Assert
        assertEquals(wifiConfig, decryptedWifi)
    }

    @Test
    fun `should handle document metadata QR code scenario`() {
        // Arrange
        val key = generateTestKey()
        val documentMetadata = """
            {
                "documentId": "DOC-2024-12345",
                "title": "Confidential Report",
                "author": "Jane Smith",
                "classification": "SECRET",
                "createdDate": "2024-01-15",
                "expiryDate": "2025-01-15",
                "checksum": "a1b2c3d4e5f6g7h8i9j0"
            }
        """.trimIndent()

        // Act
        val (encryptedDoc, iv) = QRUtils.encryptData(documentMetadata, key)
        val docQR = QRCodeGenerator.generateQRCode(encryptedDoc, 500, 500)
        val scannedDoc = QRCodeScanner.decodeQRCode(docQR)
        val decryptedDoc = QRUtils.decryptData(scannedDoc, key, iv)

        // Assert
        assertEquals(documentMetadata, decryptedDoc)
    }
}
