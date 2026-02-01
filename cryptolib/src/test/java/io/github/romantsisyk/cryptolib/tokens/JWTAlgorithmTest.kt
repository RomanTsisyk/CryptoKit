package io.github.romantsisyk.cryptolib.tokens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JWTAlgorithmTest {

    @Test
    fun `test HMAC algorithm properties`() {
        assertEquals("HS256", JWTAlgorithm.HS256.algorithmName)
        assertEquals("HmacSHA256", JWTAlgorithm.HS256.javaAlgorithm)
        assertTrue(JWTAlgorithm.HS256.isHmac())
        assertFalse(JWTAlgorithm.HS256.isRsa())

        assertEquals("HS384", JWTAlgorithm.HS384.algorithmName)
        assertEquals("HmacSHA384", JWTAlgorithm.HS384.javaAlgorithm)
        assertTrue(JWTAlgorithm.HS384.isHmac())

        assertEquals("HS512", JWTAlgorithm.HS512.algorithmName)
        assertEquals("HmacSHA512", JWTAlgorithm.HS512.javaAlgorithm)
        assertTrue(JWTAlgorithm.HS512.isHmac())
    }

    @Test
    fun `test RSA algorithm properties`() {
        assertEquals("RS256", JWTAlgorithm.RS256.algorithmName)
        assertEquals("SHA256withRSA", JWTAlgorithm.RS256.javaAlgorithm)
        assertTrue(JWTAlgorithm.RS256.isRsa())
        assertFalse(JWTAlgorithm.RS256.isHmac())

        assertEquals("RS384", JWTAlgorithm.RS384.algorithmName)
        assertEquals("SHA384withRSA", JWTAlgorithm.RS384.javaAlgorithm)
        assertTrue(JWTAlgorithm.RS384.isRsa())

        assertEquals("RS512", JWTAlgorithm.RS512.algorithmName)
        assertEquals("SHA512withRSA", JWTAlgorithm.RS512.javaAlgorithm)
        assertTrue(JWTAlgorithm.RS512.isRsa())
    }

    @Test
    fun `test fromString with valid algorithm names`() {
        assertEquals(JWTAlgorithm.HS256, JWTAlgorithm.fromString("HS256"))
        assertEquals(JWTAlgorithm.HS384, JWTAlgorithm.fromString("HS384"))
        assertEquals(JWTAlgorithm.HS512, JWTAlgorithm.fromString("HS512"))
        assertEquals(JWTAlgorithm.RS256, JWTAlgorithm.fromString("RS256"))
        assertEquals(JWTAlgorithm.RS384, JWTAlgorithm.fromString("RS384"))
        assertEquals(JWTAlgorithm.RS512, JWTAlgorithm.fromString("RS512"))
    }

    @Test
    fun `test fromString with invalid algorithm name throws exception`() {
        assertThrows(IllegalArgumentException::class.java) {
            JWTAlgorithm.fromString("INVALID")
        }
    }

    @Test
    fun `test fromString with empty string throws exception`() {
        assertThrows(IllegalArgumentException::class.java) {
            JWTAlgorithm.fromString("")
        }
    }
}
