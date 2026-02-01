package io.github.romantsisyk.cryptolib.tokens

import io.github.romantsisyk.cryptolib.exceptions.TokenException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureTokenGeneratorTest {

    @Test
    fun `test generateToken creates non-empty token`() {
        val token = SecureTokenGenerator.generateToken()

        assertNotNull(token)
        assertTrue(token.isNotEmpty())
    }

    @Test
    fun `test generateToken with default length`() {
        val token = SecureTokenGenerator.generateToken()

        // Base64 URL encoding of 32 bytes should produce ~43 characters (no padding)
        assertTrue(token.length >= 40)
    }

    @Test
    fun `test generateToken with custom length`() {
        val token = SecureTokenGenerator.generateToken(16)

        // Base64 URL encoding of 16 bytes should produce ~22 characters (no padding)
        assertTrue(token.length >= 20 && token.length <= 24)
    }

    @Test
    fun `test generateToken produces unique tokens`() {
        val token1 = SecureTokenGenerator.generateToken()
        val token2 = SecureTokenGenerator.generateToken()

        assertNotEquals(token1, token2)
    }

    @Test
    fun `test generateToken throws exception for invalid length`() {
        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateToken(0)
        }

        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateToken(-1)
        }
    }

    @Test
    fun `test generateToken is URL-safe`() {
        val token = SecureTokenGenerator.generateToken()

        // URL-safe Base64 should not contain + or / characters
        assertFalse(token.contains('+'))
        assertFalse(token.contains('/'))
        assertFalse(token.contains('=')) // No padding
    }

    @Test
    fun `test generateHexToken creates non-empty token`() {
        val token = SecureTokenGenerator.generateHexToken()

        assertNotNull(token)
        assertTrue(token.isNotEmpty())
    }

    @Test
    fun `test generateHexToken with default length`() {
        val token = SecureTokenGenerator.generateHexToken()

        // 32 bytes should produce 64 hex characters
        assertEquals(64, token.length)
    }

    @Test
    fun `test generateHexToken with custom length`() {
        val token = SecureTokenGenerator.generateHexToken(16)

        // 16 bytes should produce 32 hex characters
        assertEquals(32, token.length)
    }

    @Test
    fun `test generateHexToken produces unique tokens`() {
        val token1 = SecureTokenGenerator.generateHexToken()
        val token2 = SecureTokenGenerator.generateHexToken()

        assertNotEquals(token1, token2)
    }

    @Test
    fun `test generateHexToken contains only hex characters`() {
        val token = SecureTokenGenerator.generateHexToken()

        assertTrue(token.matches(Regex("^[0-9a-f]+$")))
    }

    @Test
    fun `test generateHexToken throws exception for invalid length`() {
        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateHexToken(0)
        }

        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateHexToken(-1)
        }
    }

    @Test
    fun `test generateNumericOTP with default digits`() {
        val otp = SecureTokenGenerator.generateNumericOTP()

        assertEquals(6, otp.length)
        assertTrue(otp.matches(Regex("^[0-9]{6}$")))
    }

    @Test
    fun `test generateNumericOTP with custom digits`() {
        val otp4 = SecureTokenGenerator.generateNumericOTP(4)
        assertEquals(4, otp4.length)

        val otp8 = SecureTokenGenerator.generateNumericOTP(8)
        assertEquals(8, otp8.length)

        val otp10 = SecureTokenGenerator.generateNumericOTP(10)
        assertEquals(10, otp10.length)
    }

    @Test
    fun `test generateNumericOTP produces unique codes`() {
        val otp1 = SecureTokenGenerator.generateNumericOTP()
        val otp2 = SecureTokenGenerator.generateNumericOTP()

        // High probability they should be different
        // Run multiple times to reduce false negatives
        val otps = (1..10).map { SecureTokenGenerator.generateNumericOTP() }
        val uniqueOtps = otps.toSet()
        assertTrue(uniqueOtps.size > 1)
    }

    @Test
    fun `test generateNumericOTP throws exception for invalid digits`() {
        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateNumericOTP(3)
        }

        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateNumericOTP(11)
        }

        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateNumericOTP(0)
        }
    }

    @Test
    fun `test generateNumericOTP does not start with zero`() {
        // Generate multiple OTPs to ensure none start with 0
        val otps = (1..20).map { SecureTokenGenerator.generateNumericOTP() }
        otps.forEach { otp ->
            assertNotEquals('0', otp[0])
        }
    }

    @Test
    fun `test generateAlphanumericToken creates non-empty token`() {
        val token = SecureTokenGenerator.generateAlphanumericToken()

        assertNotNull(token)
        assertTrue(token.isNotEmpty())
    }

    @Test
    fun `test generateAlphanumericToken with default length`() {
        val token = SecureTokenGenerator.generateAlphanumericToken()

        assertEquals(16, token.length)
    }

    @Test
    fun `test generateAlphanumericToken with custom length`() {
        val token = SecureTokenGenerator.generateAlphanumericToken(32)

        assertEquals(32, token.length)
    }

    @Test
    fun `test generateAlphanumericToken contains only alphanumeric characters`() {
        val token = SecureTokenGenerator.generateAlphanumericToken()

        assertTrue(token.matches(Regex("^[A-Za-z0-9]+$")))
    }

    @Test
    fun `test generateAlphanumericToken produces unique tokens`() {
        val token1 = SecureTokenGenerator.generateAlphanumericToken()
        val token2 = SecureTokenGenerator.generateAlphanumericToken()

        assertNotEquals(token1, token2)
    }

    @Test
    fun `test generateAlphanumericToken throws exception for invalid length`() {
        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateAlphanumericToken(0)
        }

        assertThrows(TokenException::class.java) {
            SecureTokenGenerator.generateAlphanumericToken(-1)
        }
    }

    @Test
    fun `test generateAlphanumericToken has good character distribution`() {
        val token = SecureTokenGenerator.generateAlphanumericToken(1000)

        // Check that we have uppercase, lowercase, and digits
        assertTrue(token.any { it.isUpperCase() })
        assertTrue(token.any { it.isLowerCase() })
        assertTrue(token.any { it.isDigit() })
    }

    @Test
    fun `test generateSessionId creates unique session IDs`() {
        val sessionId1 = SecureTokenGenerator.generateSessionId()
        val sessionId2 = SecureTokenGenerator.generateSessionId()

        assertNotNull(sessionId1)
        assertNotNull(sessionId2)
        assertNotEquals(sessionId1, sessionId2)
        assertTrue(sessionId1.isNotEmpty())
    }

    @Test
    fun `test generateApiKey creates unique API keys`() {
        val apiKey1 = SecureTokenGenerator.generateApiKey()
        val apiKey2 = SecureTokenGenerator.generateApiKey()

        assertNotNull(apiKey1)
        assertNotNull(apiKey2)
        assertNotEquals(apiKey1, apiKey2)
        assertTrue(apiKey1.length > 40) // Should be longer than session ID
    }

    @Test
    fun `test generateRefreshToken creates unique refresh tokens`() {
        val refreshToken1 = SecureTokenGenerator.generateRefreshToken()
        val refreshToken2 = SecureTokenGenerator.generateRefreshToken()

        assertNotNull(refreshToken1)
        assertNotNull(refreshToken2)
        assertNotEquals(refreshToken1, refreshToken2)
        assertEquals(128, refreshToken1.length) // 64 bytes = 128 hex chars
        assertTrue(refreshToken1.matches(Regex("^[0-9a-f]+$")))
    }

    @Test
    fun `test generateCsrfToken creates unique CSRF tokens`() {
        val csrfToken1 = SecureTokenGenerator.generateCsrfToken()
        val csrfToken2 = SecureTokenGenerator.generateCsrfToken()

        assertNotNull(csrfToken1)
        assertNotNull(csrfToken2)
        assertNotEquals(csrfToken1, csrfToken2)
        assertTrue(csrfToken1.isNotEmpty())
    }

    @Test
    fun `test different token types produce different formats`() {
        val sessionId = SecureTokenGenerator.generateSessionId()
        val apiKey = SecureTokenGenerator.generateApiKey()
        val refreshToken = SecureTokenGenerator.generateRefreshToken()
        val csrfToken = SecureTokenGenerator.generateCsrfToken()

        // Refresh token should be hex
        assertTrue(refreshToken.matches(Regex("^[0-9a-f]+$")))

        // Others should be Base64 URL-safe
        assertFalse(sessionId.contains('+'))
        assertFalse(apiKey.contains('+'))
        assertFalse(csrfToken.contains('+'))

        // API key should be longer than session ID
        assertTrue(apiKey.length > sessionId.length)
    }

    @Test
    fun `test token generation performance`() {
        val startTime = System.currentTimeMillis()

        // Generate 100 tokens of each type
        repeat(100) {
            SecureTokenGenerator.generateToken()
            SecureTokenGenerator.generateHexToken()
            SecureTokenGenerator.generateNumericOTP()
            SecureTokenGenerator.generateAlphanumericToken()
        }

        val endTime = System.currentTimeMillis()
        val duration = endTime - startTime

        // Should complete in reasonable time (less than 5 seconds)
        assertTrue(duration < 5000)
    }

    private fun assertFalse(condition: Boolean) {
        assertTrue(!condition)
    }
}
