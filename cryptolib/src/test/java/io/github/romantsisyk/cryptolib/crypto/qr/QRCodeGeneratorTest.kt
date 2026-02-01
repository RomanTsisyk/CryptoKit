package io.github.romantsisyk.cryptolib.crypto.qr

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
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
 * Comprehensive unit tests for QRCodeGenerator.
 * Tests QR code generation with various parameters, edge cases, and error conditions.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30], manifest = Config.NONE)
class QRCodeGeneratorTest {

    @Before
    fun setUp() {
        // Initialize any required mocks
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // ==================== Tests for successful QR code generation ====================

    @Test
    fun `generateQRCode should create bitmap with default dimensions`() {
        // Arrange
        val testData = "Test QR Code Data"

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
        assertEquals(300, bitmap.width)
        assertEquals(300, bitmap.height)
        assertEquals(Bitmap.Config.RGB_565, bitmap.config)
    }

    @Test
    fun `generateQRCode should create bitmap with custom dimensions`() {
        // Arrange
        val testData = "Custom Size QR Code"
        val customWidth = 500
        val customHeight = 500

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData, customWidth, customHeight)

        // Assert
        assertNotNull(bitmap)
        assertEquals(customWidth, bitmap.width)
        assertEquals(customHeight, bitmap.height)
    }

    @Test
    fun `generateQRCode should create bitmap with rectangular dimensions`() {
        // Arrange
        val testData = "Rectangular QR Code"
        val width = 400
        val height = 200

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData, width, height)

        // Assert
        assertNotNull(bitmap)
        assertEquals(width, bitmap.width)
        assertEquals(height, bitmap.height)
    }

    @Test
    fun `generateQRCode should create bitmap with minimum valid dimensions`() {
        // Arrange
        val testData = "Tiny QR"
        val minSize = 1

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData, minSize, minSize)

        // Assert
        assertNotNull(bitmap)
        assertEquals(minSize, bitmap.width)
        assertEquals(minSize, bitmap.height)
    }

    @Test
    fun `generateQRCode should create bitmap with maximum allowed dimensions`() {
        // Arrange
        val testData = "Maximum Size QR"
        val maxSize = 4096

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData, maxSize, maxSize)

        // Assert
        assertNotNull(bitmap)
        assertEquals(maxSize, bitmap.width)
        assertEquals(maxSize, bitmap.height)
    }

    @Test
    fun `generateQRCode should handle single character data`() {
        // Arrange
        val testData = "A"

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
    }

    @Test
    fun `generateQRCode should handle long text data`() {
        // Arrange
        val testData = "A".repeat(1000) // 1000 character string

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
    }

    @Test
    fun `generateQRCode should handle special characters`() {
        // Arrange
        val testData = "Special: !@#$%^&*()_+-={}[]|\\:\";<>?,./~`"

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
    }

    @Test
    fun `generateQRCode should handle unicode characters`() {
        // Arrange
        val testData = "Unicode: \u4E2D\u6587 \uD83D\uDE00 \u00E9\u00F1"

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
    }

    @Test
    fun `generateQRCode should handle JSON formatted data`() {
        // Arrange
        val testData = """{"key":"value","number":123,"array":[1,2,3]}"""

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
    }

    @Test
    fun `generateQRCode should handle URL formatted data`() {
        // Arrange
        val testData = "https://example.com/path?param1=value1&param2=value2"

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData)

        // Assert
        assertNotNull(bitmap)
    }

    @Test
    fun `generateQRCode should create bitmap with only black and white pixels`() {
        // Arrange
        val testData = "Color Test"

        // Act
        val bitmap = QRCodeGenerator.generateQRCode(testData, 100, 100)

        // Assert
        assertNotNull(bitmap)
        val pixels = IntArray(100 * 100)
        bitmap.getPixels(pixels, 0, 100, 0, 0, 100, 100)

        // Verify all pixels are either black or white
        pixels.forEach { pixel ->
            assert(pixel == Color.BLACK || pixel == Color.WHITE) {
                "Found pixel with color: $pixel"
            }
        }
    }

    // ==================== Tests for validation and error handling ====================

    @Test
    fun `generateQRCode should throw IllegalArgumentException for empty data`() {
        // Arrange
        val emptyData = ""

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(emptyData)
        }
        assertEquals(
            "Data string cannot be empty. Please provide a non-empty string to encode into the QR code.",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for zero width`() {
        // Arrange
        val testData = "Valid Data"
        val invalidWidth = 0

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, invalidWidth, 300)
        }
        assertEquals(
            "Width must be a positive integer. Provided value: $invalidWidth",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for negative width`() {
        // Arrange
        val testData = "Valid Data"
        val invalidWidth = -100

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, invalidWidth, 300)
        }
        assertEquals(
            "Width must be a positive integer. Provided value: $invalidWidth",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for zero height`() {
        // Arrange
        val testData = "Valid Data"
        val invalidHeight = 0

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, 300, invalidHeight)
        }
        assertEquals(
            "Height must be a positive integer. Provided value: $invalidHeight",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for negative height`() {
        // Arrange
        val testData = "Valid Data"
        val invalidHeight = -100

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, 300, invalidHeight)
        }
        assertEquals(
            "Height must be a positive integer. Provided value: $invalidHeight",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for width exceeding max dimension`() {
        // Arrange
        val testData = "Valid Data"
        val exceedingWidth = 4097

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, exceedingWidth, 300)
        }
        assertEquals(
            "Width exceeds maximum allowed dimension of 4096 pixels. Provided value: $exceedingWidth",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for height exceeding max dimension`() {
        // Arrange
        val testData = "Valid Data"
        val exceedingHeight = 5000

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, 300, exceedingHeight)
        }
        assertEquals(
            "Height exceeds maximum allowed dimension of 4096 pixels. Provided value: $exceedingHeight",
            exception.message
        )
    }

    @Test
    fun `generateQRCode should throw IllegalArgumentException for both dimensions exceeding max`() {
        // Arrange
        val testData = "Valid Data"
        val exceedingWidth = 5000
        val exceedingHeight = 6000

        // Act & Assert
        val exception = assertThrows(IllegalArgumentException::class.java) {
            QRCodeGenerator.generateQRCode(testData, exceedingWidth, exceedingHeight)
        }
        // Should fail on width check first
        assertEquals(
            "Width exceeds maximum allowed dimension of 4096 pixels. Provided value: $exceedingWidth",
            exception.message
        )
    }

    // ==================== Integration tests verifying actual QR generation ====================

    @Test
    fun `generateQRCode should produce decodable QR code`() {
        // Arrange
        val originalData = "Integration Test Data"

        // Act
        val qrBitmap = QRCodeGenerator.generateQRCode(originalData, 300, 300)
        val decodedData = QRCodeScanner.decodeQRCode(qrBitmap)

        // Assert
        assertEquals(originalData, decodedData)
    }

    @Test
    fun `generateQRCode should produce consistent output for same input`() {
        // Arrange
        val testData = "Consistency Test"

        // Act
        val bitmap1 = QRCodeGenerator.generateQRCode(testData, 200, 200)
        val bitmap2 = QRCodeGenerator.generateQRCode(testData, 200, 200)

        // Assert
        val pixels1 = IntArray(200 * 200)
        val pixels2 = IntArray(200 * 200)
        bitmap1.getPixels(pixels1, 0, 200, 0, 0, 200, 200)
        bitmap2.getPixels(pixels2, 0, 200, 0, 0, 200, 200)

        assert(pixels1.contentEquals(pixels2)) {
            "Same input should produce identical QR codes"
        }
    }

    @Test
    fun `generateQRCode should encode data with different sizes correctly`() {
        // Arrange
        val testData = "Size Variation Test"

        // Act
        val small = QRCodeGenerator.generateQRCode(testData, 100, 100)
        val medium = QRCodeGenerator.generateQRCode(testData, 300, 300)
        val large = QRCodeGenerator.generateQRCode(testData, 500, 500)

        // Assert - All should decode to same data
        assertEquals(testData, QRCodeScanner.decodeQRCode(small))
        assertEquals(testData, QRCodeScanner.decodeQRCode(medium))
        assertEquals(testData, QRCodeScanner.decodeQRCode(large))
    }
}
