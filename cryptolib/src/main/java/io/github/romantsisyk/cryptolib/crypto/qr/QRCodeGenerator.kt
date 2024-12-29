package io.github.romantsisyk.cryptolib.crypto.qr

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/**
 * Generates a QR code bitmap from the provided data string.
 *
 * @param data The string data to encode into a QR code.
 * @param width The width of the generated QR code bitmap (default is 300).
 * @param height The height of the generated QR code bitmap (default is 300).
 * @return A Bitmap object representing the generated QR code.
 * @throws IllegalArgumentException If there is an error generating the QR code.
 */
fun generateQRCode(data: String, width: Int = 300, height: Int = 300): Bitmap {
    val qrCodeWriter = QRCodeWriter()

    // Generate the bit matrix for the QR code based on the input data.
    val bitMatrix = qrCodeWriter.encode(data, BarcodeFormat.QR_CODE, width, height)

    // Create an empty Bitmap with the specified width and height.
    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

    // Loop through each pixel of the bitMatrix to set the color of the corresponding pixel in the bitmap.
    for (x in 0 until width) {
        for (y in 0 until height) {
            bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
        }
    }

    return bitmap
}