package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64

/**
 * Utility object providing Base64 encoding and decoding operations.
 * Supports both standard and URL-safe Base64 encoding schemes.
 */
object Base64Utils {

    /**
     * Encodes the provided byte array to a standard Base64 string.
     *
     * @param data The data to encode.
     * @return A Base64-encoded string.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    fun encode(data: ByteArray): String {
        return try {
            Base64.getEncoder().encodeToString(data)
        } catch (e: Exception) {
            throw CryptoOperationException("Base64 encoding failed: ${e.message}", e)
        }
    }

    /**
     * Encodes the provided byte array to a URL-safe Base64 string.
     * URL-safe encoding uses '-' and '_' instead of '+' and '/', and omits padding.
     *
     * @param data The data to encode.
     * @return A URL-safe Base64-encoded string.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    fun encodeUrlSafe(data: ByteArray): String {
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(data)
        } catch (e: Exception) {
            throw CryptoOperationException("URL-safe Base64 encoding failed: ${e.message}", e)
        }
    }

    /**
     * Decodes a standard Base64-encoded string to a byte array.
     *
     * @param encoded The Base64-encoded string to decode.
     * @return The decoded byte array.
     * @throws CryptoOperationException if the input is not valid Base64 or decoding fails.
     */
    @JvmStatic
    fun decode(encoded: String): ByteArray {
        if (encoded.isEmpty()) {
            throw CryptoOperationException("Base64 decoding failed: input cannot be empty")
        }

        return try {
            Base64.getDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw CryptoOperationException("Base64 decoding failed: invalid Base64 string", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Base64 decoding failed: ${e.message}", e)
        }
    }

    /**
     * Decodes a URL-safe Base64-encoded string to a byte array.
     *
     * @param encoded The URL-safe Base64-encoded string to decode.
     * @return The decoded byte array.
     * @throws CryptoOperationException if the input is not valid URL-safe Base64 or decoding fails.
     */
    @JvmStatic
    fun decodeUrlSafe(encoded: String): ByteArray {
        if (encoded.isEmpty()) {
            throw CryptoOperationException("URL-safe Base64 decoding failed: input cannot be empty")
        }

        return try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw CryptoOperationException("URL-safe Base64 decoding failed: invalid Base64 string", e)
        } catch (e: Exception) {
            throw CryptoOperationException("URL-safe Base64 decoding failed: ${e.message}", e)
        }
    }

    /**
     * Validates whether the provided string is valid Base64.
     *
     * @param input The string to validate.
     * @return True if the input is valid Base64, false otherwise.
     */
    @JvmStatic
    fun isValidBase64(input: String): Boolean {
        if (input.isEmpty()) {
            return false
        }

        return try {
            Base64.getDecoder().decode(input)
            true
        } catch (e: IllegalArgumentException) {
            false
        }
    }
}
