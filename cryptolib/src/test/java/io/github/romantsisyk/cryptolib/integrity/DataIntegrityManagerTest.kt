package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPair

class DataIntegrityManagerTest {

    private val testData = "Hello, World!".toByteArray()
    private lateinit var rsaKeyPair: KeyPair
    private lateinit var ecKeyPair: KeyPair

    @Before
    fun setup() {
        rsaKeyPair = DigitalSignature.generateKeyPair("RSA")
        ecKeyPair = DigitalSignature.generateKeyPair("EC")
    }

    @Test
    fun `test createIntegrityEnvelope with default algorithm`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)

        assertArrayEquals(testData, envelope.data)
        assertNotEquals("", envelope.checksum)
        assertEquals(ChecksumAlgorithm.SHA256, envelope.algorithm)
        assertTrue(envelope.timestamp > 0)
        assertTrue(envelope.timestamp <= System.currentTimeMillis())
    }

    @Test
    fun `test createIntegrityEnvelope with specific algorithm`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(
            testData,
            ChecksumAlgorithm.SHA512
        )

        assertEquals(ChecksumAlgorithm.SHA512, envelope.algorithm)
        assertEquals(128, envelope.checksum.length) // SHA512 produces 128 hex chars
    }

    @Test
    fun `test createIntegrityEnvelope with empty data throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            DataIntegrityManager.createIntegrityEnvelope(ByteArray(0))
        }
    }

    @Test
    fun `test createIntegrityEnvelope produces valid checksum`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)

        // Verify the checksum manually
        val expectedChecksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        assertEquals(expectedChecksum, envelope.checksum)
    }

    @Test
    fun `test verifyIntegrity with valid envelope returns true`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)
        val isValid = DataIntegrityManager.verifyIntegrity(envelope)

        assertTrue(isValid)
    }

    @Test
    fun `test verifyIntegrity with tampered data returns false`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)

        // Create a tampered envelope with modified data
        val tamperedEnvelope = IntegrityEnvelope(
            data = "Tampered data".toByteArray(),
            checksum = envelope.checksum,
            algorithm = envelope.algorithm,
            timestamp = envelope.timestamp
        )

        val isValid = DataIntegrityManager.verifyIntegrity(tamperedEnvelope)
        assertFalse(isValid)
    }

    @Test
    fun `test verifyIntegrity with tampered checksum returns false`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)

        // Create a tampered envelope with modified checksum
        val tamperedEnvelope = IntegrityEnvelope(
            data = envelope.data,
            checksum = "0000000000000000000000000000000000000000000000000000000000000000",
            algorithm = envelope.algorithm,
            timestamp = envelope.timestamp
        )

        val isValid = DataIntegrityManager.verifyIntegrity(tamperedEnvelope)
        assertFalse(isValid)
    }

    @Test
    fun `test signData with RSA key`() {
        val signedData = DataIntegrityManager.signData(testData, rsaKeyPair.private)

        assertArrayEquals(testData, signedData.data)
        assertNotNull(signedData.signature)
        assertTrue(signedData.signature.isNotEmpty())
        assertEquals("SHA256withRSA/PSS", signedData.signatureAlgorithm)
        assertTrue(signedData.timestamp > 0)
    }

    @Test
    fun `test signData with EC key`() {
        val signedData = DataIntegrityManager.signData(testData, ecKeyPair.private)

        assertArrayEquals(testData, signedData.data)
        assertNotNull(signedData.signature)
        assertTrue(signedData.signature.isNotEmpty())
        assertEquals("SHA256withECDSA", signedData.signatureAlgorithm)
        assertTrue(signedData.timestamp > 0)
    }

    @Test
    fun `test signData with empty data throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            DataIntegrityManager.signData(ByteArray(0), rsaKeyPair.private)
        }
    }

    @Test
    fun `test verifySignature with valid RSA signature returns true`() {
        val signedData = DataIntegrityManager.signData(testData, rsaKeyPair.private)
        val isValid = DataIntegrityManager.verifySignature(signedData, rsaKeyPair.public)

        assertTrue(isValid)
    }

    @Test
    fun `test verifySignature with valid EC signature returns true`() {
        val signedData = DataIntegrityManager.signData(testData, ecKeyPair.private)
        val isValid = DataIntegrityManager.verifySignature(signedData, ecKeyPair.public)

        assertTrue(isValid)
    }

    @Test
    fun `test verifySignature with wrong public key returns false`() {
        val signedData = DataIntegrityManager.signData(testData, rsaKeyPair.private)
        val differentKeyPair = DigitalSignature.generateKeyPair("RSA")

        val isValid = DataIntegrityManager.verifySignature(signedData, differentKeyPair.public)
        assertFalse(isValid)
    }

    @Test
    fun `test verifySignature with tampered data returns false`() {
        val signedData = DataIntegrityManager.signData(testData, rsaKeyPair.private)

        // Create tampered signed data
        val tamperedSignedData = SignedData(
            data = "Tampered".toByteArray(),
            signature = signedData.signature,
            signatureAlgorithm = signedData.signatureAlgorithm,
            timestamp = signedData.timestamp
        )

        val isValid = DataIntegrityManager.verifySignature(tamperedSignedData, rsaKeyPair.public)
        assertFalse(isValid)
    }

    @Test
    fun `test verifySignature with tampered signature returns false`() {
        val signedData = DataIntegrityManager.signData(testData, rsaKeyPair.private)

        // Create tampered signed data
        val tamperedSignedData = SignedData(
            data = signedData.data,
            signature = "tampered".toByteArray(),
            signatureAlgorithm = signedData.signatureAlgorithm,
            timestamp = signedData.timestamp
        )

        val isValid = DataIntegrityManager.verifySignature(tamperedSignedData, rsaKeyPair.public)
        assertFalse(isValid)
    }

    @Test
    fun `test createSignedEnvelope creates both envelope and signature`() {
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private
        )

        // Verify envelope
        assertArrayEquals(testData, envelope.data)
        assertEquals(ChecksumAlgorithm.SHA256, envelope.algorithm)
        assertNotEquals("", envelope.checksum)

        // Verify signed data
        assertArrayEquals(testData, signedData.data)
        assertTrue(signedData.signature.isNotEmpty())
        assertEquals("SHA256withRSA/PSS", signedData.signatureAlgorithm)

        // Verify both contain the same data
        assertArrayEquals(envelope.data, signedData.data)
    }

    @Test
    fun `test createSignedEnvelope with custom algorithm`() {
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private,
            ChecksumAlgorithm.SHA512
        )

        assertEquals(ChecksumAlgorithm.SHA512, envelope.algorithm)
        assertEquals(128, envelope.checksum.length)
    }

    @Test
    fun `test verifySignedEnvelope with valid data returns true`() {
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private
        )

        val isValid = DataIntegrityManager.verifySignedEnvelope(
            envelope,
            signedData,
            rsaKeyPair.public
        )

        assertTrue(isValid)
    }

    @Test
    fun `test verifySignedEnvelope with mismatched data returns false`() {
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)
        val signedData = DataIntegrityManager.signData("Different data".toByteArray(), rsaKeyPair.private)

        val isValid = DataIntegrityManager.verifySignedEnvelope(
            envelope,
            signedData,
            rsaKeyPair.public
        )

        assertFalse(isValid)
    }

    @Test
    fun `test verifySignedEnvelope with tampered envelope returns false`() {
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private
        )

        // Tamper with envelope checksum
        val tamperedEnvelope = IntegrityEnvelope(
            data = envelope.data,
            checksum = "0000000000000000000000000000000000000000000000000000000000000000",
            algorithm = envelope.algorithm,
            timestamp = envelope.timestamp
        )

        val isValid = DataIntegrityManager.verifySignedEnvelope(
            tamperedEnvelope,
            signedData,
            rsaKeyPair.public
        )

        assertFalse(isValid)
    }

    @Test
    fun `test verifySignedEnvelope with tampered signature returns false`() {
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private
        )

        // Tamper with signature
        val tamperedSignedData = SignedData(
            data = signedData.data,
            signature = "tampered".toByteArray(),
            signatureAlgorithm = signedData.signatureAlgorithm,
            timestamp = signedData.timestamp
        )

        val isValid = DataIntegrityManager.verifySignedEnvelope(
            envelope,
            tamperedSignedData,
            rsaKeyPair.public
        )

        assertFalse(isValid)
    }

    @Test
    fun `test verifySignedEnvelope with wrong public key returns false`() {
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private
        )

        val differentKeyPair = DigitalSignature.generateKeyPair("RSA")

        val isValid = DataIntegrityManager.verifySignedEnvelope(
            envelope,
            signedData,
            differentKeyPair.public
        )

        assertFalse(isValid)
    }

    @Test
    fun `test createIntegrityEnvelope with different algorithms`() {
        val algorithms = listOf(
            ChecksumAlgorithm.CRC32,
            ChecksumAlgorithm.ADLER32,
            ChecksumAlgorithm.MD5,
            ChecksumAlgorithm.SHA256,
            ChecksumAlgorithm.SHA512
        )

        algorithms.forEach { algorithm ->
            val envelope = DataIntegrityManager.createIntegrityEnvelope(testData, algorithm)
            assertEquals(algorithm, envelope.algorithm)
            assertTrue(DataIntegrityManager.verifyIntegrity(envelope))
        }
    }

    @Test
    fun `test complete workflow with envelope serialization`() {
        // Create envelope
        val envelope = DataIntegrityManager.createIntegrityEnvelope(testData)

        // Serialize to JSON
        val json = envelope.toJson()

        // Deserialize from JSON
        val restoredEnvelope = IntegrityEnvelope.fromJson(json)

        // Verify integrity of restored envelope
        assertTrue(DataIntegrityManager.verifyIntegrity(restoredEnvelope))
        assertEquals(envelope, restoredEnvelope)
    }

    @Test
    fun `test complete workflow with signed data serialization`() {
        // Sign data
        val signedData = DataIntegrityManager.signData(testData, rsaKeyPair.private)

        // Serialize to JSON
        val json = signedData.toJson()

        // Deserialize from JSON
        val restoredSignedData = SignedData.fromJson(json)

        // Verify signature of restored signed data
        assertTrue(DataIntegrityManager.verifySignature(restoredSignedData, rsaKeyPair.public))
        assertEquals(signedData, restoredSignedData)
    }

    @Test
    fun `test complete workflow with signed envelope serialization`() {
        // Create signed envelope
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            testData,
            rsaKeyPair.private
        )

        // Serialize both to JSON
        val envelopeJson = envelope.toJson()
        val signedDataJson = signedData.toJson()

        // Deserialize from JSON
        val restoredEnvelope = IntegrityEnvelope.fromJson(envelopeJson)
        val restoredSignedData = SignedData.fromJson(signedDataJson)

        // Verify both
        assertTrue(
            DataIntegrityManager.verifySignedEnvelope(
                restoredEnvelope,
                restoredSignedData,
                rsaKeyPair.public
            )
        )
    }
}
