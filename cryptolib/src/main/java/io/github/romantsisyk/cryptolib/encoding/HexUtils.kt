package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException

/**
 * Utility object providing hexadecimal encoding and decoding operations.
 * Supports both uppercase and lowercase hexadecimal representations.
 */
object HexUtils {

    private const val HEX_CHARS_UPPER = "0123456789ABCDEF"
    private const val HEX_CHARS_LOWER = "0123456789abcdef"

    /**
     * Encodes the provided byte array to an uppercase hexadecimal string.
     *
     * @param data The data to encode.
     * @return An uppercase hexadecimal string representation.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    fun encode(data: ByteArray): String {
        return try {
            val hexChars = CharArray(data.size * 2)
            data.forEachIndexed { i, byte ->
                val value = byte.toInt() and 0xFF
                hexChars[i * 2] = HEX_CHARS_UPPER[value ushr 4]
                hexChars[i * 2 + 1] = HEX_CHARS_UPPER[value and 0x0F]
            }
            String(hexChars)
        } catch (e: Exception) {
            throw CryptoOperationException("Hexadecimal encoding failed: ${e.message}", e)
        }
    }

    /**
     * Encodes the provided byte array to a lowercase hexadecimal string.
     *
     * @param data The data to encode.
     * @return A lowercase hexadecimal string representation.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    fun encodeLowerCase(data: ByteArray): String {
        return try {
            val hexChars = CharArray(data.size * 2)
            data.forEachIndexed { i, byte ->
                val value = byte.toInt() and 0xFF
                hexChars[i * 2] = HEX_CHARS_LOWER[value ushr 4]
                hexChars[i * 2 + 1] = HEX_CHARS_LOWER[value and 0x0F]
            }
            String(hexChars)
        } catch (e: Exception) {
            throw CryptoOperationException("Hexadecimal encoding failed: ${e.message}", e)
        }
    }

    /**
     * Decodes a hexadecimal string to a byte array.
     * Accepts both uppercase and lowercase hexadecimal characters.
     *
     * @param hex The hexadecimal string to decode.
     * @return The decoded byte array.
     * @throws CryptoOperationException if the input is not valid hexadecimal or has odd length.
     */
    @JvmStatic
    fun decode(hex: String): ByteArray {
        if (hex.isEmpty()) {
            throw CryptoOperationException("Hexadecimal decoding failed: input cannot be empty")
        }

        if (hex.length % 2 != 0) {
            throw CryptoOperationException("Hexadecimal decoding failed: input must have even length")
        }

        return try {
            val result = ByteArray(hex.length / 2)
            for (i in result.indices) {
                val index = i * 2
                val highNibble = hex[index].digitToInt(16)
                val lowNibble = hex[index + 1].digitToInt(16)
                result[i] = ((highNibble shl 4) or lowNibble).toByte()
            }
            result
        } catch (e: IllegalArgumentException) {
            throw CryptoOperationException("Hexadecimal decoding failed: invalid hexadecimal string", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Hexadecimal decoding failed: ${e.message}", e)
        }
    }

    /**
     * Validates whether the provided string is valid hexadecimal.
     *
     * @param input The string to validate.
     * @return True if the input is valid hexadecimal, false otherwise.
     */
    @JvmStatic
    fun isValidHex(input: String): Boolean {
        if (input.isEmpty() || input.length % 2 != 0) {
            return false
        }

        return try {
            input.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
        } catch (e: Exception) {
            false
        }
    }
}
