package io.github.romantsisyk.cryptolib.crypto.qr

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/**
 * Class responsible for generating QR codes.
 * The QR code is created based on a string input and then converted into a bitmap.
 */
object QRCodeGenerator {
    /**
     * Maximum allowed dimension (width or height) for the QR code bitmap.
     * This limit prevents OutOfMemoryError when creating large bitmaps.
     */
    private const val MAX_DIMENSION = 4096

    /**
     * Generates a QR code bitmap from the provided data string.
     *
     * @param data The string data to encode into a QR code.
     * @param width The width of the generated QR code bitmap (default is 300).
     * @param height The height of the generated QR code bitmap (default is 300).
     * @return A Bitmap object representing the generated QR code.
     * @throws IllegalArgumentException If data is empty, dimensions are invalid, or dimensions exceed maximum allowed size.
     */
    @JvmStatic
    fun generateQRCode(data: String, width: Int = 300, height: Int = 300): Bitmap {
        // Validate input parameters
        require(data.isNotEmpty()) {
            "Data string cannot be empty. Please provide a non-empty string to encode into the QR code."
        }
        require(width > 0) {
            "Width must be a positive integer. Provided value: $width"
        }
        require(height > 0) {
            "Height must be a positive integer. Provided value: $height"
        }
        require(width <= MAX_DIMENSION) {
            "Width exceeds maximum allowed dimension of $MAX_DIMENSION pixels. Provided value: $width"
        }
        require(height <= MAX_DIMENSION) {
            "Height exceeds maximum allowed dimension of $MAX_DIMENSION pixels. Provided value: $height"
        }

        val qrCodeWriter = QRCodeWriter()

        // Generate the bit matrix for the QR code based on the input data.
        val bitMatrix = qrCodeWriter.encode(data, BarcodeFormat.QR_CODE, width, height)

        // Create a pixel array and fill it based on the bitMatrix.
        // This is much faster than calling setPixel() in a loop for large bitmaps.
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val offset = y * width
            for (x in 0 until width) {
                pixels[offset + x] = if (bitMatrix[x, y]) Color.BLACK else Color.WHITE
            }
        }

        // Create the bitmap and set all pixels at once.
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        bitmap.setPixels(pixels, 0, width, 0, 0, width, height)

        return bitmap
    }
}