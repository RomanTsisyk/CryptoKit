package io.github.romantsisyk.cryptolib.crypto.qr

import android.graphics.Bitmap
import com.google.zxing.LuminanceSource

/**
 * Custom LuminanceSource that converts a Bitmap image into a luminance array for QR code scanning.
 *
 * @param bitmap The Bitmap image to convert into luminance values.
 */
class BitmapLuminanceSource(private val bitmap: Bitmap) : LuminanceSource(bitmap.width, bitmap.height) {

    // Array to hold the luminance values of each pixel in the bitmap.
    private val luminanceArray: ByteArray

    init {
        val width = bitmap.width
        val height = bitmap.height

        // Array to store all pixel colors of the bitmap.
        val pixels = IntArray(width * height)

        // Get the pixel data from the bitmap.
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

        // Initialize the luminanceArray to store the luminance values for each pixel.
        luminanceArray = ByteArray(width * height)

        // Iterate through each pixel and calculate its luminance.
        for (i in pixels.indices) {
            val pixel = pixels[i]

            // Extract the color components from the pixel (alpha, red, green, blue).
            val alpha = (pixel shr 24) and 0xff
            val red = (pixel shr 16) and 0xff
            val green = (pixel shr 8) and 0xff
            val blue = pixel and 0xff

            // Adjust the color components based on the alpha transparency value.
            val adjustedRed = red * alpha / 255
            val adjustedGreen = green * alpha / 255
            val adjustedBlue = blue * alpha / 255

            // Calculate the luminance value based on the adjusted color components.
            luminanceArray[i] = (0.299 * adjustedRed + 0.587 * adjustedGreen + 0.114 * adjustedBlue).toInt().toByte()
        }
    }

    /**
     * Retrieves the luminance values for a specific row of the bitmap.
     *
     * @param y The row index to retrieve.
     * @param row The existing row array to populate, or null to create a new one.
     * @return A byte array representing the luminance values of the specified row.
     */
    override fun getRow(y: Int, row: ByteArray?): ByteArray {
        val width = width
        // Create a new row array if none is provided.
        val rowArray = row ?: ByteArray(width)
        // Copy the luminance values for the specified row from the luminance array.
        System.arraycopy(luminanceArray, y * width, rowArray, 0, width)
        return rowArray
    }

    /**
     * Retrieves the complete luminance array for the entire bitmap.
     *
     * @return A byte array representing the luminance values for all pixels.
     */
    override fun getMatrix(): ByteArray = luminanceArray
}