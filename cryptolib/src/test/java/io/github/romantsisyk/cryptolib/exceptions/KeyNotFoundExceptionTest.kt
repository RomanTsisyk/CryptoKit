package io.github.romantsisyk.cryptolib.exceptions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertSame
import org.junit.Test
import java.security.KeyStoreException

/**
 * Comprehensive unit tests for KeyNotFoundException.
 * Tests verify exception messages, causes, alias handling, and inheritance hierarchy.
 */
class KeyNotFoundExceptionTest {

    @Test
    fun `test KeyNotFoundException with alias only`() {
        val alias = "my_secret_key"
        val exception = KeyNotFoundException(alias)

        assertNotNull(exception.message)
        assertNull(exception.cause)
        assertTrue(exception.message!!.contains(alias))
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
        assertSame(cause, exception.cause)
    }

    @Test
    fun `test KeyNotFoundException with empty alias`() {
        val alias = ""
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains("''"))
    }

    @Test
    fun `test KeyNotFoundException with special characters in alias`() {
        val alias = "key-with-special_chars.123"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException with whitespace in alias`() {
        val alias = "key with spaces"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException with unicode in alias`() {
        val alias = "key_密钥_🔑"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException with nested cause`() {
        val rootCause = KeyStoreException("Keystore not initialized")
        val intermediateCause = IllegalStateException("Cannot access keystore", rootCause)
        val alias = "secure_key"
        val exception = KeyNotFoundException(alias, intermediateCause)

        assertTrue(exception.message!!.contains(alias))
        assertEquals(intermediateCause, exception.cause)
        assertEquals(rootCause, exception.cause?.cause)
    }

    @Test
    fun `test KeyNotFoundException with null cause explicitly`() {
        val alias = "my_key"
        val exception = KeyNotFoundException(alias, null)

        assertTrue(exception.message!!.contains(alias))
        assertNull(exception.cause)
    }

    @Test
    fun `test KeyNotFoundException extends CryptoLibException`() {
        val exception = KeyNotFoundException("test")

        assertTrue(exception is CryptoLibException)
    }

    @Test
    fun `test KeyNotFoundException extends Exception`() {
        val exception = KeyNotFoundException("test")

        assertTrue(exception is Exception)
    }

    @Test
    fun `test KeyNotFoundException extends Throwable`() {
        val exception = KeyNotFoundException("test")

        assertTrue(exception is Throwable)
    }

    @Test
    fun `test KeyNotFoundException can be thrown and caught`() {
        val alias = "test_key"

        try {
            throw KeyNotFoundException(alias)
        } catch (e: KeyNotFoundException) {
            assertTrue(e.message!!.contains(alias))
        }
    }

    @Test
    fun `test KeyNotFoundException can be caught as CryptoLibException`() {
        val alias = "test_key"

        try {
            throw KeyNotFoundException(alias)
        } catch (e: CryptoLibException) {
            assertTrue(e.message!!.contains(alias))
            assertTrue(e is KeyNotFoundException)
        }
    }

    @Test
    fun `test KeyNotFoundException can be caught as Exception`() {
        val alias = "test_key"

        try {
            throw KeyNotFoundException(alias)
        } catch (e: Exception) {
            assertTrue(e.message!!.contains(alias))
            assertTrue(e is KeyNotFoundException)
        }
    }

    @Test
    fun `test KeyNotFoundException preserves stack trace`() {
        val exception = KeyNotFoundException("test_key")
        val stackTrace = exception.stackTrace

        assertNotNull(stackTrace)
        assertTrue(stackTrace.isNotEmpty())
    }

    @Test
    fun `test KeyNotFoundException cause preserves original exception type`() {
        val originalCause = SecurityException("Keystore locked")
        val alias = "locked_key"
        val exception = KeyNotFoundException(alias, originalCause)

        assertNotNull(exception.cause)
        assertTrue(exception.cause is SecurityException)
        assertEquals("Keystore locked", exception.cause!!.message)
    }

    @Test
    fun `test KeyNotFoundException with multiple different causes`() {
        val alias = "test_key"
        val causes = listOf(
            IllegalArgumentException("Invalid alias format"),
            SecurityException("Access denied"),
            KeyStoreException("Keystore error"),
            NullPointerException("Null reference"),
            IllegalStateException("Keystore not loaded")
        )

        causes.forEach { cause ->
            val exception = KeyNotFoundException(alias, cause)
            assertEquals(cause, exception.cause)
            assertEquals(cause.message, exception.cause?.message)
            assertTrue(exception.message!!.contains(alias))
        }
    }

    @Test
    fun `test KeyNotFoundException with different alias formats`() {
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
            val exception = KeyNotFoundException(alias)
            assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
            assertTrue(exception.message!!.contains(alias))
        }
    }

    @Test
    fun `test KeyNotFoundException message consistency`() {
        val alias = "consistent_key"
        val exception1 = KeyNotFoundException(alias)
        val exception2 = KeyNotFoundException(alias)

        assertEquals(exception1.message, exception2.message)
    }

    @Test
    fun `test KeyNotFoundException toString includes alias`() {
        val alias = "my_secret_key"
        val exception = KeyNotFoundException(alias)
        val toString = exception.toString()

        assertTrue(toString.contains("KeyNotFoundException"))
        assertTrue(toString.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException equality of causes`() {
        val alias = "test_key"
        val cause = RuntimeException("Root cause")
        val exception1 = KeyNotFoundException(alias, cause)
        val exception2 = KeyNotFoundException(alias, cause)

        assertSame(exception1.cause, exception2.cause)
    }

    @Test
    fun `test KeyNotFoundException with long alias`() {
        val alias = "a".repeat(1000)
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException with single character alias`() {
        val alias = "k"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias 'k' not found in the Keystore.", exception.message)
    }

    @Test
    fun `test KeyNotFoundException inheritance chain`() {
        val exception = KeyNotFoundException("test")

        assertTrue(exception is KeyNotFoundException)
        assertTrue(exception is CryptoLibException)
        assertTrue(exception is Exception)
        assertTrue(exception is Throwable)
    }

    @Test
    fun `test KeyNotFoundException with quote in alias`() {
        val alias = "key'with'quotes"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException with newline in alias`() {
        val alias = "key\nwith\nnewlines"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains("\n"))
    }

    @Test
    fun `test KeyNotFoundException message contains Keystore reference`() {
        val alias = "test_key"
        val exception = KeyNotFoundException(alias)

        assertTrue(exception.message!!.contains("Keystore"))
        assertTrue(exception.message!!.contains("not found"))
    }

    @Test
    fun `test KeyNotFoundException with path-like alias`() {
        val alias = "path/to/my/key"
        val exception = KeyNotFoundException(alias)

        assertEquals("Key with alias '$alias' not found in the Keystore.", exception.message)
        assertTrue(exception.message!!.contains(alias))
    }

    @Test
    fun `test KeyNotFoundException distinguishes different aliases`() {
        val alias1 = "key1"
        val alias2 = "key2"
        val exception1 = KeyNotFoundException(alias1)
        val exception2 = KeyNotFoundException(alias2)

        assertTrue(exception1.message!!.contains(alias1))
        assertTrue(exception2.message!!.contains(alias2))
        assertTrue(!exception1.message!!.contains(alias2))
        assertTrue(!exception2.message!!.contains(alias1))
    }
}
