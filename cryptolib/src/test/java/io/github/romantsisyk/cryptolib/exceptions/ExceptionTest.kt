package io.github.romantsisyk.cryptolib.exceptions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExceptionTest {

    // ==================== CryptoLibException Tests ====================

    @Test
    fun `test CryptoLibException with message only`() {
        val message = "Test error message"
        val exception = CryptoLibException(message)

        assertEquals(message, exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test CryptoLibException with message and cause`() {
        val message = "Test error message"
        val cause = RuntimeException("Root cause")
        val exception = CryptoLibException(message, cause)

        assertEquals(message, exception.message)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `test CryptoLibException extends Exception`() {
        val exception = CryptoLibException("Test")

        assertTrue(exception is Exception)
    }

    // ==================== CryptoOperationException Tests ====================

    @Test
    fun `test CryptoOperationException with message only`() {
        val message = "Encryption failed"
        val exception = CryptoOperationException(message)

        assertEquals(message, exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test CryptoOperationException with message and cause`() {
        val message = "Decryption failed"
        val cause = IllegalArgumentException("Invalid key")
        val exception = CryptoOperationException(message, cause)

        assertEquals(message, exception.message)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `test CryptoOperationException extends CryptoLibException`() {
        val exception = CryptoOperationException("Test")

        assertTrue(exception is CryptoLibException)
    }

    // ==================== KeyNotFoundException Tests ====================

    @Test
    fun `test KeyNotFoundException with alias`() {
        val alias = "my_secret_key"
        val exception = KeyNotFoundException(alias)

        assertNotNull(exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test KeyNotFoundException message format`() {
        val alias = "test_key_alias"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
    }

    @Test
    fun `test KeyNotFoundException with alias and cause`() {
        val alias = "missing_key"
        val cause = SecurityException("Keystore access denied")
        val exception = KeyNotFoundException(alias, cause)

        assertTrue(exception.message!!.contains(alias))
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `test KeyNotFoundException extends CryptoLibException`() {
        val exception = KeyNotFoundException("test")

        assertTrue(exception is CryptoLibException)
    }

    // ==================== KeyGenerationException Tests ====================

    @Test
    fun `test KeyGenerationException with alias`() {
        val alias = "new_key"
        val exception = KeyGenerationException(alias)

        assertNotNull(exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test KeyGenerationException message format`() {
        val alias = "generated_key"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
    }

    @Test
    fun `test KeyGenerationException with alias and cause`() {
        val alias = "rsa_key"
        val cause = IllegalStateException("Insufficient entropy")
        val exception = KeyGenerationException(alias, cause)

        assertTrue(exception.message!!.contains(alias))
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `test KeyGenerationException extends CryptoLibException`() {
        val exception = KeyGenerationException("test")

        assertTrue(exception is CryptoLibException)
    }

    // ==================== AuthenticationException Tests ====================

    @Test
    fun `test AuthenticationException with message only`() {
        val message = "Authentication failed"
        val exception = AuthenticationException(message)

        assertEquals(message, exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test AuthenticationException with message and cause`() {
        val message = "Invalid credentials"
        val cause = SecurityException("Token expired")
        val exception = AuthenticationException(message, cause)

        assertEquals(message, exception.message)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `test AuthenticationException extends CryptoLibException`() {
        val exception = AuthenticationException("Test")

        assertTrue(exception is CryptoLibException)
    }

    // ==================== Exception Hierarchy Tests ====================

    @Test
    fun `verify all exceptions extend CryptoLibException`() {
        val cryptoOpException = CryptoOperationException("test")
        val keyNotFoundException = KeyNotFoundException("alias")
        val keyGenException = KeyGenerationException("alias")
        val authException = AuthenticationException("test")

        assertTrue("CryptoOperationException should extend CryptoLibException",
            cryptoOpException is CryptoLibException)
        assertTrue("KeyNotFoundException should extend CryptoLibException",
            keyNotFoundException is CryptoLibException)
        assertTrue("KeyGenerationException should extend CryptoLibException",
            keyGenException is CryptoLibException)
        assertTrue("AuthenticationException should extend CryptoLibException",
            authException is CryptoLibException)
    }

    @Test
    fun `verify all exceptions are catchable as CryptoLibException`() {
        val exceptions = listOf<CryptoLibException>(
            CryptoOperationException("Operation failed"),
            KeyNotFoundException("missing_key"),
            KeyGenerationException("gen_key"),
            AuthenticationException("Auth failed")
        )

        exceptions.forEach { exception ->
            try {
                throw exception
            } catch (e: CryptoLibException) {
                // Successfully caught as CryptoLibException
                assertNotNull(e.message)
            }
        }
    }

    @Test
    fun `verify exception inheritance chain`() {
        val exception = CryptoOperationException("test")

        // CryptoOperationException -> CryptoLibException -> Exception -> Throwable
        assertTrue(exception is CryptoOperationException)
        assertTrue(exception is CryptoLibException)
        assertTrue(exception is Exception)
        assertTrue(exception is Throwable)
    }
}
