package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RandomStringGeneratorTest {

    @Test
    fun `test generateAlphanumeric returns correct length`() {
        val length = 20
        val result = RandomStringGenerator.generateAlphanumeric(length)
        assertEquals(length, result.length)
    }

    @Test
    fun `test generateAlphanumeric contains only alphanumeric characters`() {
        val result = RandomStringGenerator.generateAlphanumeric(100)
        val alphanumericPattern = Regex("^[A-Za-z0-9]+$")
        assertTrue(result.matches(alphanumericPattern))
    }

    @Test
    fun `test generateAlphanumeric produces different results`() {
        val result1 = RandomStringGenerator.generateAlphanumeric(50)
        val result2 = RandomStringGenerator.generateAlphanumeric(50)
        assertNotEquals(result1, result2)
    }

    @Test
    fun `test generateAlphanumeric throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateAlphanumeric(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateAlphanumeric(-1)
        }
    }

    @Test
    fun `test generateAlphabetic returns correct length`() {
        val length = 20
        val result = RandomStringGenerator.generateAlphabetic(length)
        assertEquals(length, result.length)
    }

    @Test
    fun `test generateAlphabetic contains only alphabetic characters`() {
        val result = RandomStringGenerator.generateAlphabetic(100)
        val alphabeticPattern = Regex("^[A-Za-z]+$")
        assertTrue(result.matches(alphabeticPattern))
    }

    @Test
    fun `test generateAlphabetic throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateAlphabetic(0)
        }
    }

    @Test
    fun `test generateNumeric returns correct length`() {
        val length = 20
        val result = RandomStringGenerator.generateNumeric(length)
        assertEquals(length, result.length)
    }

    @Test
    fun `test generateNumeric contains only digits`() {
        val result = RandomStringGenerator.generateNumeric(100)
        val numericPattern = Regex("^[0-9]+$")
        assertTrue(result.matches(numericPattern))
    }

    @Test
    fun `test generateNumeric throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateNumeric(0)
        }
    }

    @Test
    fun `test generateHex returns correct length`() {
        val length = 20
        val result = RandomStringGenerator.generateHex(length)
        assertEquals(length, result.length)
    }

    @Test
    fun `test generateHex contains only hexadecimal characters`() {
        val result = RandomStringGenerator.generateHex(100)
        val hexPattern = Regex("^[0-9a-f]+$")
        assertTrue(result.matches(hexPattern))
    }

    @Test
    fun `test generateHex throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateHex(0)
        }
    }

    @Test
    fun `test generateBase64 produces valid Base64 string`() {
        val result = RandomStringGenerator.generateBase64(32)
        // Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
        val base64Pattern = Regex("^[A-Za-z0-9+/]+=*$")
        assertTrue(result.matches(base64Pattern))
    }

    @Test
    fun `test generateBase64 produces different results`() {
        val result1 = RandomStringGenerator.generateBase64(32)
        val result2 = RandomStringGenerator.generateBase64(32)
        assertNotEquals(result1, result2)
    }

    @Test
    fun `test generateBase64 throws exception for non-positive byteLength`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateBase64(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateBase64(-1)
        }
    }

    @Test
    fun `test generateFromCharset returns correct length`() {
        val length = 30
        val charset = "ABC123"
        val result = RandomStringGenerator.generateFromCharset(length, charset)
        assertEquals(length, result.length)
    }

    @Test
    fun `test generateFromCharset uses only characters from charset`() {
        val charset = "XYZ"
        val result = RandomStringGenerator.generateFromCharset(100, charset)
        result.forEach { char ->
            assertTrue(charset.contains(char))
        }
    }

    @Test
    fun `test generateFromCharset throws exception for empty charset`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateFromCharset(10, "")
        }
    }

    @Test
    fun `test generateFromCharset throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generateFromCharset(0, "ABC")
        }
    }

    @Test
    fun `test generatePassword returns correct length`() {
        val length = 16
        val result = RandomStringGenerator.generatePassword(length)
        assertEquals(length, result.length)
    }

    @Test
    fun `test generatePassword with all character types enabled contains all types`() {
        val password = RandomStringGenerator.generatePassword(
            length = 100,
            includeUppercase = true,
            includeLowercase = true,
            includeDigits = true,
            includeSpecial = true
        )

        assertTrue(password.any { it in 'A'..'Z' })
        assertTrue(password.any { it in 'a'..'z' })
        assertTrue(password.any { it in '0'..'9' })
        assertTrue(password.any { it in "!@#$%^&*()-_=+[]{}|;:,.<>?" })
    }

    @Test
    fun `test generatePassword with only uppercase`() {
        val password = RandomStringGenerator.generatePassword(
            length = 50,
            includeUppercase = true,
            includeLowercase = false,
            includeDigits = false,
            includeSpecial = false
        )

        assertTrue(password.all { it in 'A'..'Z' })
    }

    @Test
    fun `test generatePassword with only lowercase`() {
        val password = RandomStringGenerator.generatePassword(
            length = 50,
            includeUppercase = false,
            includeLowercase = true,
            includeDigits = false,
            includeSpecial = false
        )

        assertTrue(password.all { it in 'a'..'z' })
    }

    @Test
    fun `test generatePassword with only digits`() {
        val password = RandomStringGenerator.generatePassword(
            length = 50,
            includeUppercase = false,
            includeLowercase = false,
            includeDigits = true,
            includeSpecial = false
        )

        assertTrue(password.all { it in '0'..'9' })
    }

    @Test
    fun `test generatePassword with only special characters`() {
        val password = RandomStringGenerator.generatePassword(
            length = 50,
            includeUppercase = false,
            includeLowercase = false,
            includeDigits = false,
            includeSpecial = true
        )

        assertTrue(password.all { it in "!@#$%^&*()-_=+[]{}|;:,.<>?" })
    }

    @Test
    fun `test generatePassword throws exception when no character types enabled`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generatePassword(
                length = 10,
                includeUppercase = false,
                includeLowercase = false,
                includeDigits = false,
                includeSpecial = false
            )
        }
    }

    @Test
    fun `test generatePassword throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generatePassword(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generatePassword(-1)
        }
    }

    @Test
    fun `test generatePassword throws exception when length is too short for enabled types`() {
        assertThrows(CryptoOperationException::class.java) {
            RandomStringGenerator.generatePassword(
                length = 2,
                includeUppercase = true,
                includeLowercase = true,
                includeDigits = true,
                includeSpecial = true
            )
        }
    }

    @Test
    fun `test generatePassword produces different results`() {
        val password1 = RandomStringGenerator.generatePassword(20)
        val password2 = RandomStringGenerator.generatePassword(20)
        assertNotEquals(password1, password2)
    }

    @Test
    fun `test generatePassword minimum length matches enabled types`() {
        // With 4 types enabled, minimum length should be 4
        val password = RandomStringGenerator.generatePassword(
            length = 4,
            includeUppercase = true,
            includeLowercase = true,
            includeDigits = true,
            includeSpecial = true
        )
        assertEquals(4, password.length)
    }

    @Test
    fun `test generateFromCharset with single character charset`() {
        val result = RandomStringGenerator.generateFromCharset(10, "X")
        assertEquals("XXXXXXXXXX", result)
    }

    @Test
    fun `test generateAlphanumeric with length 1`() {
        val result = RandomStringGenerator.generateAlphanumeric(1)
        assertEquals(1, result.length)
        val alphanumericPattern = Regex("^[A-Za-z0-9]$")
        assertTrue(result.matches(alphanumericPattern))
    }
}
