package io.github.romantsisyk.cryptolib.crypto.qr

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BinaryBitmap
import com.google.zxing.NotFoundException
import com.google.zxing.Result
import com.google.zxing.qrcode.QRCodeReader
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Comprehensive unit tests for QRCodeScanner.
 * Tests QR code decoding with various scenarios and error conditions.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30], manifest = Config.NONE)
class QRCodeScannerTest {

    @Before
    fun setUp() {
        // Initialize any required mocks
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // ==================== Tests for successful QR code scanning ====================

    @Test
    fun `decodeQRCode should decode simple text QR code`() {
        // Arrange
        val originalData = "Simple Test Data"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode single character QR code`() {
        // Arrange
        val originalData = "X"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode long text QR code`() {
        // Arrange
        val originalData = "This is a much longer test string that contains multiple words and sentences. " +
                "It should still be decoded correctly by the QR code scanner implementation."
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData, 500, 500)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with special characters`() {
        // Arrange
        val originalData = "Special: !@#$%^&*()_+-={}[]|\\:\";<>?,./~`"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with unicode characters`() {
        // Arrange
        val originalData = "Unicode: \u4E2D\u6587 \u00E9\u00F1"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with numeric data`() {
        // Arrange
        val originalData = "1234567890"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with alphanumeric data`() {
        // Arrange
        val originalData = "ABC123XYZ789"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with JSON data`() {
        // Arrange
        val originalData = """{"key":"value","number":123,"bool":true}"""
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with URL data`() {
        // Arrange
        val originalData = "https://example.com/api/endpoint?param1=value1&param2=value2"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with Base64 encoded data`() {
        // Arrange
        val originalData = "SGVsbG8gV29ybGQ="  // "Hello World" in Base64
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with newline characters`() {
        // Arrange
        val originalData = "Line1\nLine2\nLine3"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode QR code with tab characters`() {
        // Arrange
        val originalData = "Column1\tColumn2\tColumn3"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode small QR code`() {
        // Arrange
        val originalData = "Small"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData, 100, 100)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode large QR code`() {
        // Arrange
        val originalData = "Large QR Code Test"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData, 1000, 1000)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `decodeQRCode should decode rectangular QR code`() {
        // Arrange
        val originalData = "Rectangular Test"
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData, 400, 200)

        // Act
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    // ==================== Tests for error handling ====================

    @Test
    fun `decodeQRCode should throw IllegalArgumentException for blank bitmap`() {
        // Arrange - Create a completely white (blank) bitmap
        val blankBitmap = Bitmap.createBitmap(300, 300, Bitmap.Config.RGB_565)
        blankBitmap.eraseColor(Color.WHITE)

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeScanner.decodeQRCode(blankBitmap)
        }
        assertNotNull(exception.message)
        assert(exception.message!!.contains("Error decoding QR Code"))
    }

    @Test
    fun `decodeQRCode should throw IllegalArgumentException for solid black bitmap`() {
        // Arrange - Create a completely black bitmap
        val blackBitmap = Bitmap.createBitmap(300, 300, Bitmap.Config.RGB_565)
        blackBitmap.eraseColor(Color.BLACK)

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeScanner.decodeQRCode(blackBitmap)
        }
        assertNotNull(exception.message)
        assert(exception.message!!.contains("Error decoding QR Code"))
    }

    @Test
    fun `decodeQRCode should throw IllegalArgumentException for random noise bitmap`() {
        // Arrange - Create a bitmap with random pixels (not a QR code)
        val noiseBitmap = Bitmap.createBitmap(300, 300, Bitmap.Config.RGB_565)
        val pixels = IntArray(300 * 300) { if (it % 2 == 0) Color.BLACK else Color.WHITE }
        noiseBitmap.setPixels(pixels, 0, 300, 0, 0, 300, 300)

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeScanner.decodeQRCode(noiseBitmap)
        }
        assertNotNull(exception.message)
        assert(exception.message!!.contains("Error decoding QR Code"))
    }

    @Test
    fun `decodeQRCode should throw IllegalArgumentException for very small bitmap`() {
        // Arrange - Create a tiny bitmap that's too small to contain a valid QR code
        val tinyBitmap = Bitmap.createBitmap(10, 10, Bitmap.Config.RGB_565)
        tinyBitmap.eraseColor(Color.WHITE)

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeScanner.decodeQRCode(tinyBitmap)
        }
        assertNotNull(exception.message)
        assert(exception.message!!.contains("Error decoding QR Code"))
    }

    // ==================== Integration tests ====================

    @Test
    fun `decodeQRCode should handle encode-decode round trip correctly`() {
        // Arrange
        val testData = "Round Trip Test Data"

        // Act
        val encodedBitmap = QRCodeGenerator.generateQRCode(testData)
        val decodedData = QRCodeScanner.decodeQRCode(encodedBitmap)

        // Assert
        assertEquals(testData, decodedData)
    }

    @Test
    fun `decodeQRCode should handle multiple encode-decode cycles`() {
        // Arrange
        val testData = "Multiple Cycles Test"

        // Act & Assert - Multiple rounds
        repeat(5) {
            val bitmap = QRCodeGenerator.generateQRCode(testData)
            val decoded = QRCodeScanner.decodeQRCode(bitmap)
            assertEquals(testData, decoded)
        }
    }

    @Test
    fun `decodeQRCode should correctly decode QR codes of different sizes with same data`() {
        // Arrange
        val testData = "Size Independence Test"

        // Act
        val small = QRCodeGenerator.generateQRCode(testData, 150, 150)
        val medium = QRCodeGenerator.generateQRCode(testData, 300, 300)
        val large = QRCodeGenerator.generateQRCode(testData, 600, 600)

        // Assert
        assertEquals(testData, QRCodeScanner.decodeQRCode(small))
        assertEquals(testData, QRCodeScanner.decodeQRCode(medium))
        assertEquals(testData, QRCodeScanner.decodeQRCode(large))
    }

    @Test
    fun `decodeQRCode should correctly decode multiple different QR codes`() {
        // Arrange
        val data1 = "First QR Code"
        val data2 = "Second QR Code"
        val data3 = "Third QR Code"

        // Act
        val qr1 = QRCodeGenerator.generateQRCode(data1)
        val qr2 = QRCodeGenerator.generateQRCode(data2)
        val qr3 = QRCodeGenerator.generateQRCode(data3)

        // Assert
        assertEquals(data1, QRCodeScanner.decodeQRCode(qr1))
        assertEquals(data2, QRCodeScanner.decodeQRCode(qr2))
        assertEquals(data3, QRCodeScanner.decodeQRCode(qr3))
    }

    @Test
    fun `decodeQRCode should preserve data integrity with complex content`() {
        // Arrange
        val complexData = """
            {
                "transaction": "0x123abc456def",
                "amount": 1000.50,
                "timestamp": "2024-01-15T10:30:00Z",
                "metadata": {
                    "source": "mobile_app",
                    "version": "2.1.0"
                }
            }
        """.trimIndent()

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(complexData, 500, 500)
        val decoded = QRCodeScanner.decodeQRCode(bitmap)

        // Assert
        assertEquals(complexData, decoded)
    }
}
