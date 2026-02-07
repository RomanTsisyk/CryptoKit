package io.github.romantsisyk.cryptolib.crypto.digital

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.*
import org.junit.Test

class DigitalSignatureTest {

    @Test
    fun `test digital signature verification`() {
        val keyPair = DigitalSignature.generateKeyPair()
        val message = "This is a signed message.".toByteArray()
        val signature = DigitalSignature.sign(message, keyPair.private)

        assertTrue(DigitalSignature.verify(message, signature, keyPair.public))
    }

    @Test
    fun `test digital signature verification with tampered message`() {
        val keyPair = DigitalSignature.generateKeyPair()
        val message = "Original message.".toByteArray()
        val tamperedMessage = "Tampered message.".toByteArray()
        val signature = DigitalSignature.sign(message, keyPair.private)

        assertFalse(DigitalSignature.verify(tamperedMessage, signature, keyPair.public))
    }

    @Test
    fun `test ECDSA signature generation and verification`() {
        val keyPair = DigitalSignature.generateKeyPair("EC")
        val message = "This is a message signed with ECDSA.".toByteArray()
        val signature = DigitalSignature.sign(message, keyPair.private)

        assertTrue(DigitalSignature.verify(message, signature, keyPair.public))
    }

    @Test
    fun `test ECDSA signature verification with tampered message`() {
        val keyPair = DigitalSignature.generateKeyPair("EC")
        val message = "Original ECDSA message.".toByteArray()
        val tamperedMessage = "Tampered ECDSA message.".toByteArray()
        val signature = DigitalSignature.sign(message, keyPair.private)

        assertFalse(DigitalSignature.verify(tamperedMessage, signature, keyPair.public))
    }

    @Test
    fun `test signing empty message works`() {
        val rsaKeyPair = DigitalSignature.generateKeyPair("RSA")
        val ecKeyPair = DigitalSignature.generateKeyPair("EC")
        val emptyMessage = ByteArray(0)

        // Test RSA with empty message
        val rsaSignature = DigitalSignature.sign(emptyMessage, rsaKeyPair.private)
        assertTrue(rsaSignature.isNotEmpty())
        assertTrue(DigitalSignature.verify(emptyMessage, rsaSignature, rsaKeyPair.public))

        // Test ECDSA with empty message
        val ecSignature = DigitalSignature.sign(emptyMessage, ecKeyPair.private)
        assertTrue(ecSignature.isNotEmpty())
        assertTrue(DigitalSignature.verify(emptyMessage, ecSignature, ecKeyPair.public))
    }

    @Test
    fun `test verifying with wrong RSA key returns false`() {
        val keyPair1 = DigitalSignature.generateKeyPair("RSA")
        val keyPair2 = DigitalSignature.generateKeyPair("RSA")
        val message = "Message signed with key pair 1.".toByteArray()

        val signature = DigitalSignature.sign(message, keyPair1.private)

        // Verify with wrong public key should return false
        assertFalse(DigitalSignature.verify(message, signature, keyPair2.public))
    }

    @Test
    fun `test verifying with wrong EC key returns false`() {
        val keyPair1 = DigitalSignature.generateKeyPair("EC")
        val keyPair2 = DigitalSignature.generateKeyPair("EC")
        val message = "Message signed with EC key pair 1.".toByteArray()

        val signature = DigitalSignature.sign(message, keyPair1.private)

        // Verify with wrong public key should return false
        assertFalse(DigitalSignature.verify(message, signature, keyPair2.public))
    }

    @Test(expected = CryptoOperationException::class)
    fun `test generateKeyPair with unsupported algorithm throws CryptoOperationException`() {
        DigitalSignature.generateKeyPair("DSA")
    }
}