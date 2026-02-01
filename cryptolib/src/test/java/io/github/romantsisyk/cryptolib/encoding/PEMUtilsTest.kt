package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey

class PEMUtilsTest {

    private fun generateRSAKeyPair() = KeyPairGenerator.getInstance("RSA").apply {
        initialize(2048)
    }.generateKeyPair()

    @Test
    fun `test encodeToPEM and decodePublicKeyFromPEM for RSA`() {
        val keyPair = generateRSAKeyPair()
        val publicKey = keyPair.public

        val pem = PEMUtils.encodeToPEM(publicKey)
        val decoded = PEMUtils.decodePublicKeyFromPEM(pem)

        assertNotNull(decoded)
        assertEquals(publicKey.algorithm, decoded.algorithm)
        assertArrayEquals(publicKey.encoded, decoded.encoded)
    }

    @Test
    fun `test encodeToPEM and decodePrivateKeyFromPEM for RSA`() {
        val keyPair = generateRSAKeyPair()
        val privateKey = keyPair.private

        val pem = PEMUtils.encodeToPEM(privateKey)
        val decoded = PEMUtils.decodePrivateKeyFromPEM(pem)

        assertNotNull(decoded)
        assertEquals(privateKey.algorithm, decoded.algorithm)
        assertArrayEquals(privateKey.encoded, decoded.encoded)
    }

    @Test
    fun `test encodeToPEM with custom type for public key`() {
        val keyPair = generateRSAKeyPair()
        val publicKey = keyPair.public

        val pem = PEMUtils.encodeToPEM(publicKey, "RSA PUBLIC KEY")

        assertTrue(pem.contains("-----BEGIN RSA PUBLIC KEY-----"))
        assertTrue(pem.contains("-----END RSA PUBLIC KEY-----"))
    }

    @Test
    fun `test encodeToPEM with custom type for private key`() {
        val keyPair = generateRSAKeyPair()
        val privateKey = keyPair.private

        val pem = PEMUtils.encodeToPEM(privateKey, "RSA PRIVATE KEY")

        assertTrue(pem.contains("-----BEGIN RSA PRIVATE KEY-----"))
        assertTrue(pem.contains("-----END RSA PRIVATE KEY-----"))
    }

    @Test
    fun `test PEM format has proper structure`() {
        val keyPair = generateRSAKeyPair()
        val publicKey = keyPair.public

        val pem = PEMUtils.encodeToPEM(publicKey)

        // Check for proper header and footer
        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertTrue(pem.endsWith("-----END PUBLIC KEY-----"))

        // Check for line breaks
        val lines = pem.lines()
        assertTrue(lines.size > 2) // At least header, content, footer

        // Check that content lines are not too long (should be 64 chars max for PEM)
        val contentLines = lines.filter { !it.startsWith("-----") }
        contentLines.forEach { line ->
            assertTrue(line.length <= 64)
        }
    }

    @Test
    fun `test isPEMFormat with valid PEM returns true`() {
        val keyPair = generateRSAKeyPair()
        val pem = PEMUtils.encodeToPEM(keyPair.public)

        assertTrue(PEMUtils.isPEMFormat(pem))
    }

    @Test
    fun `test isPEMFormat with invalid input returns false`() {
        assertFalse(PEMUtils.isPEMFormat("not a PEM format"))
        assertFalse(PEMUtils.isPEMFormat(""))
        assertFalse(PEMUtils.isPEMFormat("   "))
        assertFalse(PEMUtils.isPEMFormat("-----BEGIN ONLY"))
    }

    @Test
    fun `test decodePublicKeyFromPEM with invalid PEM throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            PEMUtils.decodePublicKeyFromPEM("invalid PEM content")
        }
    }

    @Test
    fun `test decodePrivateKeyFromPEM with invalid PEM throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            PEMUtils.decodePrivateKeyFromPEM("invalid PEM content")
        }
    }

    @Test
    fun `test decodePublicKeyFromPEM with empty content throws CryptoOperationException`() {
        val invalidPEM = """
            -----BEGIN PUBLIC KEY-----
            -----END PUBLIC KEY-----
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            PEMUtils.decodePublicKeyFromPEM(invalidPEM)
        }
    }

    @Test
    fun `test decodePublicKeyFromPEM with malformed base64 throws CryptoOperationException`() {
        val invalidPEM = """
            -----BEGIN PUBLIC KEY-----
            !!!invalid base64@@@
            -----END PUBLIC KEY-----
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            PEMUtils.decodePublicKeyFromPEM(invalidPEM)
        }
    }

    @Test
    fun `test encodeToPEM produces consistent output`() {
        val keyPair = generateRSAKeyPair()
        val publicKey = keyPair.public

        val pem1 = PEMUtils.encodeToPEM(publicKey)
        val pem2 = PEMUtils.encodeToPEM(publicKey)

        assertEquals(pem1, pem2)
    }

    @Test
    fun `test roundtrip encoding for both public and private keys`() {
        val keyPair = generateRSAKeyPair()

        // Public key roundtrip
        val publicPEM = PEMUtils.encodeToPEM(keyPair.public)
        val decodedPublic = PEMUtils.decodePublicKeyFromPEM(publicPEM)
        assertArrayEquals(keyPair.public.encoded, decodedPublic.encoded)

        // Private key roundtrip
        val privatePEM = PEMUtils.encodeToPEM(keyPair.private)
        val decodedPrivate = PEMUtils.decodePrivateKeyFromPEM(privatePEM)
        assertArrayEquals(keyPair.private.encoded, decodedPrivate.encoded)
    }

    @Test
    fun `test PEM format contains only valid base64 characters in content`() {
        val keyPair = generateRSAKeyPair()
        val pem = PEMUtils.encodeToPEM(keyPair.public)

        val contentLines = pem.lines()
            .filter { !it.startsWith("-----") }
            .joinToString("")

        // Base64 alphabet: A-Z, a-z, 0-9, +, /, =
        assertTrue(contentLines.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in listOf('+', '/', '=') })
    }

    @Test
    fun `test decodePrivateKeyFromPEM with different algorithms`() {
        val keyPair = generateRSAKeyPair()
        val privateKey = keyPair.private

        val pem = PEMUtils.encodeToPEM(privateKey)

        // Should work with explicit RSA
        val decoded = PEMUtils.decodePrivateKeyFromPEM(pem, "RSA")
        assertNotNull(decoded)
        assertArrayEquals(privateKey.encoded, decoded.encoded)
    }

    @Test
    fun `test isPEMFormat recognizes different PEM types`() {
        val publicPEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
            -----END PUBLIC KEY-----
        """.trimIndent()

        val privatePEM = """
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA
            -----END PRIVATE KEY-----
        """.trimIndent()

        assertTrue(PEMUtils.isPEMFormat(publicPEM))
        assertTrue(PEMUtils.isPEMFormat(privatePEM))
    }

    @Test
    fun `test encodeToPEM default types`() {
        val keyPair = generateRSAKeyPair()

        val publicPEM = PEMUtils.encodeToPEM(keyPair.public as PublicKey)
        val privatePEM = PEMUtils.encodeToPEM(keyPair.private as PrivateKey)

        assertTrue(publicPEM.contains("PUBLIC KEY"))
        assertTrue(privatePEM.contains("PRIVATE KEY"))
    }
}
