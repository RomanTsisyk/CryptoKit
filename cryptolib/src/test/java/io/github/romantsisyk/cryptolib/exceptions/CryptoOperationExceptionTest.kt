package io.github.romantsisyk.cryptolib.exceptions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertSame
import org.junit.Test
import java.io.IOException

/**
 * Comprehensive unit tests for CryptoOperationException.
 * Tests verify exception messages, causes, and inheritance hierarchy.
 */
class CryptoOperationExceptionTest {

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
        assertSame(cause, exception.cause)
    }

    @Test
    fun `test CryptoOperationException with empty message`() {
        val message = ""
        val exception = CryptoOperationException(message)

        assertEquals(message, exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test CryptoOperationException with complex error message`() {
        val message = "AES-GCM encryption failed: Invalid IV length. Expected 12 bytes, got 8 bytes."
        val exception = CryptoOperationException(message)

        assertEquals(message, exception.message)
        assertTrue(exception.message!!.contains("AES-GCM"))
        assertTrue(exception.message!!.contains("IV length"))
    }

    @Test
    fun `test CryptoOperationException with nested cause`() {
        val rootCause = IOException("File not found")
        val intermediateCause = RuntimeException("Failed to read key", rootCause)
        val exception = CryptoOperationException("Encryption operation failed", intermediateCause)

        assertEquals("Encryption operation failed", exception.message)
        assertEquals(intermediateCause, exception.cause)
        assertEquals(rootCause, exception.cause?.cause)
    }

    @Test
    fun `test CryptoOperationException with null cause explicitly`() {
        val message = "Operation failed"
        val exception = CryptoOperationException(message, null)

        assertEquals(message, exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `test CryptoOperationException extends CryptoLibException`() {
        val exception = CryptoOperationException("Test")

        assertTrue(exception is CryptoLibException)
    }

    @Test
    fun `test CryptoOperationException extends Exception`() {
        val exception = CryptoOperationException("Test")

        assertTrue(exception is Exception)
    }

    @Test
    fun `test CryptoOperationException extends Throwable`() {
        val exception = CryptoOperationException("Test")

        assertTrue(exception is Throwable)
    }

    @Test
    fun `test CryptoOperationException can be thrown and caught`() {
        val message = "Test exception"

        try {
            throw CryptoOperationException(message)
        } catch (e: CryptoOperationException) {
            assertEquals(message, e.message)
        }
    }

    @Test
    fun `test CryptoOperationException can be caught as CryptoLibException`() {
        val message = "Test exception"

        try {
            throw CryptoOperationException(message)
        } catch (e: CryptoLibException) {
            assertEquals(message, e.message)
            assertTrue(e is CryptoOperationException)
        }
    }

    @Test
    fun `test CryptoOperationException can be caught as Exception`() {
        val message = "Test exception"

        try {
            throw CryptoOperationException(message)
        } catch (e: Exception) {
            assertEquals(message, e.message)
            assertTrue(e is CryptoOperationException)
        }
    }

    @Test
    fun `test CryptoOperationException preserves stack trace`() {
        val exception = CryptoOperationException("Test exception")
        val stackTrace = exception.stackTrace

        assertNotNull(stackTrace)
        assertTrue(stackTrace.isNotEmpty())
    }

    @Test
    fun `test CryptoOperationException cause preserves original exception type`() {
        val originalCause = SecurityException("Keystore access denied")
        val exception = CryptoOperationException("Crypto operation failed", originalCause)

        assertNotNull(exception.cause)
        assertTrue(exception.cause is SecurityException)
        assertEquals("Keystore access denied", exception.cause!!.message)
    }

    @Test
    fun `test CryptoOperationException with multiple different causes`() {
        // Test with different exception types as causes
        val causes = listOf(
            IllegalArgumentException("Invalid argument"),
            SecurityException("Security violation"),
            IOException("I/O error"),
            NullPointerException("Null value"),
            IllegalStateException("Invalid state")
        )

        causes.forEach { cause ->
            val exception = CryptoOperationException("Operation failed", cause)
            assertEquals(cause, exception.cause)
            assertEquals(cause.message, exception.cause?.message)
        }
    }

    @Test
    fun `test CryptoOperationException message immutability`() {
        val message = "Original message"
        val exception = CryptoOperationException(message)

        assertEquals(message, exception.message)
        // Exception messages are immutable by design
        assertEquals("Original message", exception.message)
    }

    @Test
    fun `test CryptoOperationException with special characters in message`() {
        val message = "Error: AES encryption failed!\n\tInvalid key: 'test_key'\n\tCipher: \"AES/GCM/NoPadding\""
        val exception = CryptoOperationException(message)

        assertEquals(message, exception.message)
        assertTrue(exception.message!!.contains("\n"))
        assertTrue(exception.message!!.contains("\t"))
        assertTrue(exception.message!!.contains("'"))
        assertTrue(exception.message!!.contains("\""))
    }

    @Test
    fun `test CryptoOperationException equality of causes`() {
        val cause = RuntimeException("Root cause")
        val exception1 = CryptoOperationException("Test", cause)
        val exception2 = CryptoOperationException("Test", cause)

        // Both exceptions should have the same cause reference
        assertSame(exception1.cause, exception2.cause)
    }

    @Test
    fun `test CryptoOperationException toString includes message`() {
        val message = "Encryption failed"
        val exception = CryptoOperationException(message)
        val toString = exception.toString()

        assertTrue(toString.contains("CryptoOperationException"))
        assertTrue(toString.contains(message))
    }

    @Test
    fun `test CryptoOperationException inheritance chain`() {
        val exception = CryptoOperationException("test")

        // Verify complete inheritance chain
        assertTrue(exception is CryptoOperationException)
        assertTrue(exception is CryptoLibException)
        assertTrue(exception is Exception)
        assertTrue(exception is Throwable)
    }
}
