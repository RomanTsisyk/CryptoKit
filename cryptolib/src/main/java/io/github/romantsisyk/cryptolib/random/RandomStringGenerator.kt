package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64

/**
 * Object responsible for generating cryptographically secure random strings.
 * Provides methods for generating alphanumeric, alphabetic, numeric, hex, base64,
 * and custom charset strings, as well as secure passwords.
 */
object RandomStringGenerator {

    private const val UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"
    private const val DIGITS = "0123456789"
    private const val SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    private const val HEX_CHARACTERS = "0123456789abcdef"

    /**
     * Generates a cryptographically secure random alphanumeric string (A-Z, a-z, 0-9).
     *
     * @param length The length of the string to generate. Must be positive.
     * @return A random alphanumeric string of the specified length.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    fun generateAlphanumeric(length: Int): String {
        val charset = UPPERCASE_LETTERS + LOWERCASE_LETTERS + DIGITS
        return generateFromCharset(length, charset)
    }

    /**
     * Generates a cryptographically secure random alphabetic string (A-Z, a-z).
     *
     * @param length The length of the string to generate. Must be positive.
     * @return A random alphabetic string of the specified length.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    fun generateAlphabetic(length: Int): String {
        val charset = UPPERCASE_LETTERS + LOWERCASE_LETTERS
        return generateFromCharset(length, charset)
    }

    /**
     * Generates a cryptographically secure random numeric string (0-9).
     *
     * @param length The length of the string to generate. Must be positive.
     * @return A random numeric string of the specified length.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    fun generateNumeric(length: Int): String {
        return generateFromCharset(length, DIGITS)
    }

    /**
     * Generates a cryptographically secure random hexadecimal string (0-9, a-f).
     *
     * @param length The length of the string to generate. Must be positive.
     * @return A random hexadecimal string of the specified length.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    fun generateHex(length: Int): String {
        return generateFromCharset(length, HEX_CHARACTERS)
    }

    /**
     * Generates a cryptographically secure random Base64-encoded string.
     *
     * @param byteLength The number of random bytes to generate before encoding. Must be positive.
     * @return A random Base64-encoded string.
     * @throws CryptoOperationException if the byteLength is less than or equal to 0.
     */
    @JvmStatic
    fun generateBase64(byteLength: Int): String {
        if (byteLength <= 0) {
            throw CryptoOperationException("Random Base64 generation failed: byteLength must be positive")
        }

        return try {
            val randomBytes = SecureRandomGenerator.generateBytes(byteLength)
            Base64.getEncoder().encodeToString(randomBytes)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Random Base64 generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random string from a custom character set.
     *
     * @param length The length of the string to generate. Must be positive.
     * @param charset The character set to use for generation. Must not be empty.
     * @return A random string of the specified length using characters from the charset.
     * @throws CryptoOperationException if the length is less than or equal to 0 or charset is empty.
     */
    @JvmStatic
    fun generateFromCharset(length: Int, charset: String): String {
        if (length <= 0) {
            throw CryptoOperationException("Random string generation failed: length must be positive")
        }

        if (charset.isEmpty()) {
            throw CryptoOperationException("Random string generation failed: charset cannot be empty")
        }

        return try {
            val result = StringBuilder(length)
            repeat(length) {
                val index = SecureRandomGenerator.generateInt(charset.length)
                result.append(charset[index])
            }
            result.toString()
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Random string generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random password with customizable character sets.
     *
     * @param length The length of the password to generate. Must be at least 4 if all character types are enabled.
     * @param includeUppercase Whether to include uppercase letters (A-Z). Default is true.
     * @param includeLowercase Whether to include lowercase letters (a-z). Default is true.
     * @param includeDigits Whether to include digits (0-9). Default is true.
     * @param includeSpecial Whether to include special characters. Default is true.
     * @return A random password of the specified length.
     * @throws CryptoOperationException if the length is less than or equal to 0,
     *         or if no character types are enabled, or if length is too short for enabled types.
     */
    @JvmStatic
    @JvmOverloads
    fun generatePassword(
        length: Int,
        includeUppercase: Boolean = true,
        includeLowercase: Boolean = true,
        includeDigits: Boolean = true,
        includeSpecial: Boolean = true
    ): String {
        if (length <= 0) {
            throw CryptoOperationException("Password generation failed: length must be positive")
        }

        // Build the charset based on enabled character types
        val charset = StringBuilder()
        if (includeUppercase) charset.append(UPPERCASE_LETTERS)
        if (includeLowercase) charset.append(LOWERCASE_LETTERS)
        if (includeDigits) charset.append(DIGITS)
        if (includeSpecial) charset.append(SPECIAL_CHARACTERS)

        if (charset.isEmpty()) {
            throw CryptoOperationException(
                "Password generation failed: at least one character type must be enabled"
            )
        }

        return try {
            // Calculate minimum required length
            val requiredTypes = listOfNotNull(
                if (includeUppercase) UPPERCASE_LETTERS else null,
                if (includeLowercase) LOWERCASE_LETTERS else null,
                if (includeDigits) DIGITS else null,
                if (includeSpecial) SPECIAL_CHARACTERS else null
            )

            if (length < requiredTypes.size) {
                throw CryptoOperationException(
                    "Password generation failed: length must be at least ${requiredTypes.size} for the enabled character types"
                )
            }

            // Generate password ensuring at least one character from each enabled type
            val password = CharArray(length)

            // First, add at least one character from each required type
            var position = 0
            requiredTypes.forEach { typeCharset ->
                val index = SecureRandomGenerator.generateInt(typeCharset.length)
                password[position++] = typeCharset[index]
            }

            // Fill the remaining positions with random characters from the full charset
            val charsetStr = charset.toString()
            while (position < length) {
                val index = SecureRandomGenerator.generateInt(charsetStr.length)
                password[position++] = charsetStr[index]
            }

            // Shuffle the password to avoid predictable patterns
            val passwordList = password.toMutableList()
            SecureRandomGenerator.shuffle(passwordList)

            String(passwordList.toCharArray())
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Password generation failed", e)
        }
    }
}
