package io.github.romantsisyk.cryptolib.crypto.qr

import android.graphics.Bitmap
import com.google.zxing.BinaryBitmap
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException

/**
 * Class responsible for scanning and decoding QR codes from a bitmap.
 * This uses the ZXing library to decode QR codes.
 */
object QRCodeScanner {

    /**
     * Decodes the QR code from the provided Bitmap.
     *
     * @param bitmap The bitmap to scan and decode.
     * @return The string content of the decoded QR code.
     * @throws CryptoOperationException If the QR code cannot be decoded.
     */
    @JvmStatic
    fun decodeQRCode(bitmap: Bitmap): String {
        try {
            val luminanceSource = BitmapLuminanceSource(bitmap)
            val binaryBitmap = BinaryBitmap(HybridBinarizer(luminanceSource))
            val reader = QRCodeReader()

            // Attempt to decode the QR code.
            val result = reader.decode(binaryBitmap)

            // Return the decoded string.
            return result.text
        } catch (e: Exception) {
            throw CryptoOperationException("Error decoding QR Code: ${e.message}", e)
        }
    }
}