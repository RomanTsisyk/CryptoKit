package io.github.romantsisyk.cryptolib.tokens

import io.github.romantsisyk.cryptolib.exceptions.TokenException
import java.security.SecureRandom
import java.util.Base64

/**
 * Object responsible for generating secure random tokens.
 * Provides methods for generating various types of tokens including Base64, hex, numeric OTP, and alphanumeric tokens.
 */
object SecureTokenGenerator {

    /**
     * Shared SecureRandom instance for generating cryptographically secure random values.
     * Uses getInstanceStrong() to ensure the strongest available algorithm is used,
     * with a fallback to the default SecureRandom if strong instance is unavailable.
     */
    private val secureRandom: SecureRandom by lazy {
        try {
            SecureRandom.getInstanceStrong()
        } catch (e: Exception) {
            SecureRandom()
        }
    }

    /**
     * Generates a secure random token encoded in Base64 URL-safe format.
     * @param length The number of random bytes to generate (default: 32).
     * @return A Base64 URL-safe encoded token string.
     * @throws TokenException if length is less than 1.
     */
    @JvmStatic
    @JvmOverloads
    fun generateToken(length: Int = 32): String {
        if (length < 1) {
            throw TokenException("Token length must be at least 1 byte")
        }

        return try {
            val randomBytes = ByteArray(length)
            secureRandom.nextBytes(randomBytes)
            Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)
        } catch (e: Exception) {
            throw TokenException("Failed to generate secure token", e)
        }
    }

    /**
     * Generates a secure random token in hexadecimal format.
     * @param length The number of random bytes to generate (default: 32).
     * @return A hexadecimal encoded token string (2 characters per byte).
     * @throws TokenException if length is less than 1.
     */
    @JvmStatic
    @JvmOverloads
    fun generateHexToken(length: Int = 32): String {
        if (length < 1) {
            throw TokenException("Token length must be at least 1 byte")
        }

        return try {
            val randomBytes = ByteArray(length)
            secureRandom.nextBytes(randomBytes)
            randomBytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            throw TokenException("Failed to generate hex token", e)
        }
    }

    /**
     * Generates a secure numeric One-Time Password (OTP).
     * @param digits The number of digits in the OTP (default: 6, range: 4-10).
     * @return A numeric OTP string.
     * @throws TokenException if digits is not in the valid range (4-10).
     */
    @JvmStatic
    @JvmOverloads
    fun generateNumericOTP(digits: Int = 6): String {
        if (digits < 4 || digits > 10) {
            throw TokenException("OTP digits must be between 4 and 10")
        }

        return try {
            val maxValue = Math.pow(10.0, digits.toDouble()).toInt()
            val minValue = Math.pow(10.0, (digits - 1).toDouble()).toInt()
            val randomValue = secureRandom.nextInt(maxValue - minValue) + minValue
            randomValue.toString()
        } catch (e: Exception) {
            throw TokenException("Failed to generate numeric OTP", e)
        }
    }

    /**
     * Generates a secure alphanumeric token (A-Z, a-z, 0-9).
     * @param length The number of characters in the token (default: 16).
     * @return An alphanumeric token string.
     * @throws TokenException if length is less than 1.
     */
    @JvmStatic
    @JvmOverloads
    fun generateAlphanumericToken(length: Int = 16): String {
        if (length < 1) {
            throw TokenException("Token length must be at least 1 character")
        }

        return try {
            val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            val token = StringBuilder(length)

            for (i in 0 until length) {
                val randomIndex = secureRandom.nextInt(chars.length)
                token.append(chars[randomIndex])
            }

            token.toString()
        } catch (e: Exception) {
            throw TokenException("Failed to generate alphanumeric token", e)
        }
    }

    /**
     * Generates a secure random session ID.
     * This is a convenience method that generates a 32-byte token in Base64 URL-safe format.
     * @return A session ID string.
     */
    @JvmStatic
    fun generateSessionId(): String {
        return generateToken(32)
    }

    /**
     * Generates a secure API key.
     * This is a convenience method that generates a 48-byte token in Base64 URL-safe format.
     * @return An API key string.
     */
    @JvmStatic
    fun generateApiKey(): String {
        return generateToken(48)
    }

    /**
     * Generates a secure refresh token.
     * This is a convenience method that generates a 64-byte token in hexadecimal format.
     * @return A refresh token string.
     */
    @JvmStatic
    fun generateRefreshToken(): String {
        return generateHexToken(64)
    }

    /**
     * Generates a secure CSRF token.
     * This is a convenience method that generates a 32-byte token in Base64 URL-safe format.
     * @return A CSRF token string.
     */
    @JvmStatic
    fun generateCsrfToken(): String {
        return generateToken(32)
    }
}
