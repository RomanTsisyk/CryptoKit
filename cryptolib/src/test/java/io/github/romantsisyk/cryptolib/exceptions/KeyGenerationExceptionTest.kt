package io.github.romantsisyk.cryptolib.exceptions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertSame
import org.junit.Test
import java.security.KeyStoreException

/**
 * Comprehensive unit tests for KeyGenerationException.
 * Tests verify exception messages, causes, alias handling, and inheritance hierarchy.
 */
class KeyGenerationExceptionTest {

    @Test
    fun `test KeyGenerationException with alias only`() {
        val alias = "new_key"
        val exception = KeyGenerationException(alias)

        assertNotNull(exception.message)
        assertNull(exception.cause)
        assertTrue(exception.message!!.contains(alias))
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
        assertSame(cause, exception.cause)
    }

    @Test
    fun `test KeyGenerationException with empty alias`() {
        val alias = ""
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias ''.", exception.message)
        assertTrue(exception.message!!.contains("''"))
    }

    @Test
    fun `test KeyGenerationException with special characters in alias`() {
        val alias = "key-with-special_chars.123"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyGenerationException with whitespace in alias`() {
        val alias = "key with spaces"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyGenerationException with unicode in alias`() {
        val alias = "key_密钥_🔑"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyGenerationException with nested cause`() {
        val rootCause = KeyStoreException("Keystore not initialized")
        val intermediateCause = IllegalStateException("Key generation setup failed", rootCause)
        val alias = "test_key"
        val exception = KeyGenerationException(alias, intermediateCause)

        assertTrue(exception.message!!.contains(alias))
        assertEquals(intermediateCause, exception.cause)
        assertEquals(rootCause, exception.cause?.cause)
    }

    @Test
    fun `test KeyGenerationException with null cause explicitly`() {
        val alias = "my_key"
        val exception = KeyGenerationException(alias, null)

        assertTrue(exception.message!!.contains(alias))
        assertNull(exception.cause)
    }

    @Test
    fun `test KeyGenerationException extends CryptoLibException`() {
        val exception = KeyGenerationException("test")

        assertTrue(exception is CryptoLibException)
    }

    @Test
    fun `test KeyGenerationException extends Exception`() {
        val exception = KeyGenerationException("test")

        assertTrue(exception is Exception)
    }

    @Test
    fun `test KeyGenerationException extends Throwable`() {
        val exception = KeyGenerationException("test")

        assertTrue(exception is Throwable)
    }

    @Test
    fun `test KeyGenerationException can be thrown and caught`() {
        val alias = "test_key"

        try {
            throw KeyGenerationException(alias)
        } catch (e: KeyGenerationException) {
            assertTrue(e.message!!.contains(alias))
        }
    }

    @Test
    fun `test KeyGenerationException can be caught as CryptoLibException`() {
        val alias = "test_key"

        try {
            throw KeyGenerationException(alias)
        } catch (e: CryptoLibException) {
            assertTrue(e.message!!.contains(alias))
            assertTrue(e is KeyGenerationException)
        }
    }

    @Test
    fun `test KeyGenerationException can be caught as Exception`() {
        val alias = "test_key"

        try {
            throw KeyGenerationException(alias)
        } catch (e: Exception) {
            assertTrue(e.message!!.contains(alias))
            assertTrue(e is KeyGenerationException)
        }
    }

    @Test
    fun `test KeyGenerationException preserves stack trace`() {
        val exception = KeyGenerationException("test_key")
        val stackTrace = exception.stackTrace

        assertNotNull(stackTrace)
        assertTrue(stackTrace.isNotEmpty())
    }

    @Test
    fun `test KeyGenerationException cause preserves original exception type`() {
        val originalCause = SecurityException("Keystore access denied")
        val alias = "secure_key"
        val exception = KeyGenerationException(alias, originalCause)

        assertNotNull(exception.cause)
        assertTrue(exception.cause is SecurityException)
        assertEquals("Keystore access denied", exception.cause!!.message)
    }

    @Test
    fun `test KeyGenerationException with multiple different causes`() {
        val alias = "test_key"
        val causes = listOf(
            IllegalArgumentException("Invalid key size"),
            SecurityException("Algorithm not permitted"),
            KeyStoreException("Keystore error"),
            NullPointerException("Required parameter is null"),
            IllegalStateException("Invalid key state")
        )

        causes.forEach { cause ->
            val exception = KeyGenerationException(alias, cause)
            assertEquals(cause, exception.cause)
            assertEquals(cause.message, exception.cause?.message)
            assertTrue(exception.message!!.contains(alias))
        }
    }

    @Test
    fun `test KeyGenerationException with different alias formats`() {
        val aliases = listOf(
            "simple_alias",
            "UPPERCASE_ALIAS",
            "MixedCase_Alias",
            "alias-with-dashes",
            "alias.with.dots",
            "alias_123_numbers",
            "very_long_alias_name_with_many_characters_to_test_length_handling"
        )

        aliases.forEach { alias ->
            val exception = KeyGenerationException(alias)
            assertEquals("Failed to generate key with alias '$alias'.", exception.message)
            assertTrue(exception.message!!.contains(alias))
        }
    }

    @Test
    fun `test KeyGenerationException message consistency`() {
        val alias = "consistent_key"
        val exception1 = KeyGenerationException(alias)
        val exception2 = KeyGenerationException(alias)

        assertEquals(exception1.message, exception2.message)
    }

    @Test
    fun `test KeyGenerationException toString includes alias`() {
        val alias = "my_secret_key"
        val exception = KeyGenerationException(alias)
        val toString = exception.toString()

        assertTrue(toString.contains("KeyGenerationException"))
        assertTrue(toString.contains(alias))
    }

    @Test
    fun `test KeyGenerationException equality of causes`() {
        val alias = "test_key"
        val cause = RuntimeException("Root cause")
        val exception1 = KeyGenerationException(alias, cause)
        val exception2 = KeyGenerationException(alias, cause)

        assertSame(exception1.cause, exception2.cause)
    }

    @Test
    fun `test KeyGenerationException with long alias`() {
        val alias = "a".repeat(1000)
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyGenerationException with single character alias`() {
        val alias = "k"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias 'k'.", exception.message)
    }

    @Test
    fun `test KeyGenerationException inheritance chain`() {
        val exception = KeyGenerationException("test")

        assertTrue(exception is KeyGenerationException)
        assertTrue(exception is CryptoLibException)
        assertTrue(exception is Exception)
        assertTrue(exception is Throwable)
    }

    @Test
    fun `test KeyGenerationException with quote in alias`() {
        val alias = "key'with'quotes"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyGenerationException with newline in alias`() {
        val alias = "key\nwith\nnewlines"
        val exception = KeyGenerationException(alias)

        assertEquals("Failed to generate key with alias '$alias'.", exception.message)
        assertTrue(exception.message!!.contains("\n"))
    }
}
