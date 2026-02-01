package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

/**
 * Combined utility object providing various encoding and decoding operations.
 * Serves as a convenient facade for common encoding operations including Base64, hexadecimal,
 * and string-to-byte conversions.
 */
object EncodingUtils {

    /**
     * Converts a byte array to a string using the specified charset.
     *
     * @param data The byte array to convert.
     * @param charset The charset to use for conversion (defaults to UTF-8).
     * @return The resulting string.
     * @throws CryptoOperationException if conversion fails.
     */
    @JvmStatic
    @JvmOverloads
    fun bytesToString(data: ByteArray, charset: Charset = StandardCharsets.UTF_8): String {
        return try {
            String(data, charset)
        } catch (e: Exception) {
            throw CryptoOperationException("Bytes to string conversion failed: ${e.message}", e)
        }
    }

    /**
     * Converts a string to a byte array using the specified charset.
     *
     * @param str The string to convert.
     * @param charset The charset to use for conversion (defaults to UTF-8).
     * @return The resulting byte array.
     * @throws CryptoOperationException if conversion fails.
     */
    @JvmStatic
    @JvmOverloads
    fun stringToBytes(str: String, charset: Charset = StandardCharsets.UTF_8): ByteArray {
        return try {
            str.toByteArray(charset)
        } catch (e: Exception) {
            throw CryptoOperationException("String to bytes conversion failed: ${e.message}", e)
        }
    }

    /**
     * Encodes a byte array to a standard Base64 string.
     * Convenience method delegating to Base64Utils.encode().
     *
     * @param data The data to encode.
     * @return A Base64-encoded string.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    fun toBase64(data: ByteArray): String {
        return Base64Utils.encode(data)
    }

    /**
     * Decodes a Base64 string to a byte array.
     * Convenience method delegating to Base64Utils.decode().
     *
     * @param encoded The Base64-encoded string to decode.
     * @return The decoded byte array.
     * @throws CryptoOperationException if decoding fails.
     */
    @JvmStatic
    fun fromBase64(encoded: String): ByteArray {
        return Base64Utils.decode(encoded)
    }

    /**
     * Encodes a byte array to an uppercase hexadecimal string.
     * Convenience method delegating to HexUtils.encode().
     *
     * @param data The data to encode.
     * @return A hexadecimal string representation.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    fun toHex(data: ByteArray): String {
        return HexUtils.encode(data)
    }

    /**
     * Decodes a hexadecimal string to a byte array.
     * Convenience method delegating to HexUtils.decode().
     *
     * @param hex The hexadecimal string to decode.
     * @return The decoded byte array.
     * @throws CryptoOperationException if decoding fails.
     */
    @JvmStatic
    fun fromHex(hex: String): ByteArray {
        return HexUtils.decode(hex)
    }
}
