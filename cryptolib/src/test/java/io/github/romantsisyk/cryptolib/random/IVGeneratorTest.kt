package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class IVGeneratorTest {

    @Test
    fun `test generateIV with default size returns 12 bytes`() {
        val iv = IVGenerator.generateIV()
        assertEquals(12, iv.size)
    }

    @Test
    fun `test generateIV with custom size returns correct length`() {
        val customSize = 16
        val iv = IVGenerator.generateIV(customSize)
        assertEquals(customSize, iv.size)
    }

    @Test
    fun `test generateIV produces different IVs`() {
        val iv1 = IVGenerator.generateIV()
        val iv2 = IVGenerator.generateIV()
        assertFalse(iv1.contentEquals(iv2))
    }

    @Test
    fun `test generateIV throws exception for non-positive size`() {
        assertThrows(CryptoOperationException::class.java) {
            IVGenerator.generateIV(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            IVGenerator.generateIV(-1)
        }
    }

    @Test
    fun `test generateIV16 returns 16 bytes`() {
        val iv = IVGenerator.generateIV16()
        assertEquals(16, iv.size)
    }

    @Test
    fun `test generateIV16 produces different IVs`() {
        val iv1 = IVGenerator.generateIV16()
        val iv2 = IVGenerator.generateIV16()
        assertFalse(iv1.contentEquals(iv2))
    }

    @Test
    fun `test generateNonce with default size returns 12 bytes`() {
        val nonce = IVGenerator.generateNonce()
        assertEquals(12, nonce.size)
    }

    @Test
    fun `test generateNonce with custom size returns correct length`() {
        val customSize = 24
        val nonce = IVGenerator.generateNonce(customSize)
        assertEquals(customSize, nonce.size)
    }

    @Test
    fun `test generateNonce produces different nonces`() {
        val nonce1 = IVGenerator.generateNonce()
        val nonce2 = IVGenerator.generateNonce()
        assertFalse(nonce1.contentEquals(nonce2))
    }

    @Test
    fun `test generateNonce throws exception for non-positive size`() {
        assertThrows(CryptoOperationException::class.java) {
            IVGenerator.generateNonce(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            IVGenerator.generateNonce(-1)
        }
    }

    @Test
    fun `test generateIV with size 1 returns 1 byte`() {
        val iv = IVGenerator.generateIV(1)
        assertEquals(1, iv.size)
    }

    @Test
    fun `test generateIV with large size returns correct length`() {
        val largeSize = 256
        val iv = IVGenerator.generateIV(largeSize)
        assertEquals(largeSize, iv.size)
    }

    @Test
    fun `test generateNonce with size 1 returns 1 byte`() {
        val nonce = IVGenerator.generateNonce(1)
        assertEquals(1, nonce.size)
    }

    @Test
    fun `test generateNonce with large size returns correct length`() {
        val largeSize = 128
        val nonce = IVGenerator.generateNonce(largeSize)
        assertEquals(largeSize, nonce.size)
    }

    @Test
    fun `test multiple generateIV calls produce unique values`() {
        val ivs = List(100) { IVGenerator.generateIV() }
        val uniqueIVs = ivs.map { it.contentToString() }.toSet()
        assertEquals(100, uniqueIVs.size)
    }

    @Test
    fun `test multiple generateIV16 calls produce unique values`() {
        val ivs = List(100) { IVGenerator.generateIV16() }
        val uniqueIVs = ivs.map { it.contentToString() }.toSet()
        assertEquals(100, uniqueIVs.size)
    }

    @Test
    fun `test multiple generateNonce calls produce unique values`() {
        val nonces = List(100) { IVGenerator.generateNonce() }
        val uniqueNonces = nonces.map { it.contentToString() }.toSet()
        assertEquals(100, uniqueNonces.size)
    }

    @Test
    fun `test generateIV for GCM recommended size`() {
        // GCM recommended IV size is 12 bytes (96 bits)
        val iv = IVGenerator.generateIV(12)
        assertEquals(12, iv.size)
    }

    @Test
    fun `test generateIV for CBC block size`() {
        // CBC IV size should match block size (16 bytes / 128 bits for AES)
        val iv = IVGenerator.generateIV(16)
        assertEquals(16, iv.size)
    }
}
