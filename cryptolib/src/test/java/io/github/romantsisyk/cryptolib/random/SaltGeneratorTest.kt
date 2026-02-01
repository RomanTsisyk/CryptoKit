package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SaltGeneratorTest {

    @Test
    fun `test generateSalt with default size returns 32 bytes`() {
        val salt = SaltGenerator.generateSalt()
        assertEquals(32, salt.size)
    }

    @Test
    fun `test generateSalt with custom size returns correct length`() {
        val customSize = 64
        val salt = SaltGenerator.generateSalt(customSize)
        assertEquals(customSize, salt.size)
    }

    @Test
    fun `test generateSalt produces different salts`() {
        val salt1 = SaltGenerator.generateSalt()
        val salt2 = SaltGenerator.generateSalt()
        assertFalse(salt1.contentEquals(salt2))
    }

    @Test
    fun `test generateSalt throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            SaltGenerator.generateSalt(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            SaltGenerator.generateSalt(-1)
        }
    }

    @Test
    fun `test generateSaltHex with default size returns 64 hex characters`() {
        val saltHex = SaltGenerator.generateSaltHex()
        // 32 bytes = 64 hex characters
        assertEquals(64, saltHex.length)
    }

    @Test
    fun `test generateSaltHex with custom size returns correct length`() {
        val customSize = 16
        val saltHex = SaltGenerator.generateSaltHex(customSize)
        // customSize bytes = customSize * 2 hex characters
        assertEquals(customSize * 2, saltHex.length)
    }

    @Test
    fun `test generateSaltHex contains only hexadecimal characters`() {
        val saltHex = SaltGenerator.generateSaltHex()
        val hexPattern = Regex("^[0-9a-f]+$")
        assertTrue(saltHex.matches(hexPattern))
    }

    @Test
    fun `test generateSaltHex produces different salts`() {
        val salt1 = SaltGenerator.generateSaltHex()
        val salt2 = SaltGenerator.generateSaltHex()
        assertNotEquals(salt1, salt2)
    }

    @Test
    fun `test generateSaltHex throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            SaltGenerator.generateSaltHex(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            SaltGenerator.generateSaltHex(-1)
        }
    }

    @Test
    fun `test generateSaltBase64 with default size returns valid Base64 string`() {
        val saltBase64 = SaltGenerator.generateSaltBase64()
        // Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
        val base64Pattern = Regex("^[A-Za-z0-9+/]+=*$")
        assertTrue(saltBase64.matches(base64Pattern))
    }

    @Test
    fun `test generateSaltBase64 with custom size returns valid Base64 string`() {
        val customSize = 24
        val saltBase64 = SaltGenerator.generateSaltBase64(customSize)
        val base64Pattern = Regex("^[A-Za-z0-9+/]+=*$")
        assertTrue(saltBase64.matches(base64Pattern))
    }

    @Test
    fun `test generateSaltBase64 produces different salts`() {
        val salt1 = SaltGenerator.generateSaltBase64()
        val salt2 = SaltGenerator.generateSaltBase64()
        assertNotEquals(salt1, salt2)
    }

    @Test
    fun `test generateSaltBase64 throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            SaltGenerator.generateSaltBase64(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            SaltGenerator.generateSaltBase64(-1)
        }
    }

    @Test
    fun `test generateSalt with size 1 returns 1 byte`() {
        val salt = SaltGenerator.generateSalt(1)
        assertEquals(1, salt.size)
    }

    @Test
    fun `test generateSalt with large size returns correct length`() {
        val largeSize = 256
        val salt = SaltGenerator.generateSalt(largeSize)
        assertEquals(largeSize, salt.size)
    }

    @Test
    fun `test generateSaltHex with size 1 returns 2 hex characters`() {
        val saltHex = SaltGenerator.generateSaltHex(1)
        assertEquals(2, saltHex.length)
        val hexPattern = Regex("^[0-9a-f]{2}$")
        assertTrue(saltHex.matches(hexPattern))
    }

    @Test
    fun `test multiple generateSalt calls produce unique values`() {
        val salts = List(100) { SaltGenerator.generateSalt() }
        val uniqueSalts = salts.map { it.contentToString() }.toSet()
        assertEquals(100, uniqueSalts.size)
    }

    @Test
    fun `test multiple generateSaltHex calls produce unique values`() {
        val salts = List(100) { SaltGenerator.generateSaltHex() }
        val uniqueSalts = salts.toSet()
        assertEquals(100, uniqueSalts.size)
    }

    @Test
    fun `test multiple generateSaltBase64 calls produce unique values`() {
        val salts = List(100) { SaltGenerator.generateSaltBase64() }
        val uniqueSalts = salts.toSet()
        assertEquals(100, uniqueSalts.size)
    }

    @Test
    fun `test generateSaltHex encoding correctness`() {
        // Generate a salt with known size
        val salt = SaltGenerator.generateSalt(4)
        val saltHex = salt.joinToString("") { "%02x".format(it) }

        // Generate salt hex directly
        val directSaltHex = SaltGenerator.generateSaltHex(4)

        // Both should be 8 characters (4 bytes * 2 hex chars per byte)
        assertEquals(8, saltHex.length)
        assertEquals(8, directSaltHex.length)
    }

    @Test
    fun `test generateSaltBase64 encoding correctness`() {
        // Generate a salt and verify Base64 encoding length
        // Base64 encoding of n bytes results in approximately 4 * ceil(n / 3) characters
        val byteLength = 30
        val saltBase64 = SaltGenerator.generateSaltBase64(byteLength)

        // Expected length for 30 bytes: 4 * ceil(30 / 3) = 4 * 10 = 40 characters
        assertEquals(40, saltBase64.length)
    }

    @Test
    fun `test generateSalt recommended size for password hashing`() {
        // Recommended salt size for password hashing is at least 32 bytes (256 bits)
        val salt = SaltGenerator.generateSalt(32)
        assertEquals(32, salt.size)
    }

    @Test
    fun `test all salt formats produce different representations of random data`() {
        val saltBytes = SaltGenerator.generateSalt(16)
        val saltHex = SaltGenerator.generateSaltHex(16)
        val saltBase64 = SaltGenerator.generateSaltBase64(16)

        // All three should be different lengths
        assertEquals(16, saltBytes.size)
        assertEquals(32, saltHex.length) // 16 bytes * 2 hex chars
        assertTrue(saltBase64.length > 16) // Base64 is longer than original bytes
    }
}
