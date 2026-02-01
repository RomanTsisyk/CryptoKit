package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityEnvelopeTest {

    private val testData = "Hello, World!".toByteArray()
    private val testChecksum = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    private val testAlgorithm = ChecksumAlgorithm.SHA256
    private val testTimestamp = System.currentTimeMillis()

    @Test
    fun `test IntegrityEnvelope creation`() {
        val envelope = IntegrityEnvelope(
            data = testData,
            checksum = testChecksum,
            algorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        assertArrayEquals(testData, envelope.data)
        assertEquals(testChecksum, envelope.checksum)
        assertEquals(testAlgorithm, envelope.algorithm)
        assertEquals(testTimestamp, envelope.timestamp)
    }

    @Test
    fun `test toJson creates valid JSON string`() {
        val envelope = IntegrityEnvelope(
            data = testData,
            checksum = testChecksum,
            algorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        val json = envelope.toJson()

        assertTrue(json.contains("\"data\":"))
        assertTrue(json.contains("\"checksum\":\"$testChecksum\""))
        assertTrue(json.contains("\"algorithm\":\"${testAlgorithm.name}\""))
        assertTrue(json.contains("\"timestamp\":$testTimestamp"))
    }

    @Test
    fun `test fromJson creates IntegrityEnvelope from valid JSON`() {
        val envelope = IntegrityEnvelope(
            data = testData,
            checksum = testChecksum,
            algorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        val json = envelope.toJson()
        val parsedEnvelope = IntegrityEnvelope.fromJson(json)

        assertArrayEquals(envelope.data, parsedEnvelope.data)
        assertEquals(envelope.checksum, parsedEnvelope.checksum)
        assertEquals(envelope.algorithm, parsedEnvelope.algorithm)
        assertEquals(envelope.timestamp, parsedEnvelope.timestamp)
    }

    @Test
    fun `test toJson and fromJson round trip preserves data`() {
        val originalEnvelope = IntegrityEnvelope(
            data = testData,
            checksum = testChecksum,
            algorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        val json = originalEnvelope.toJson()
        val restoredEnvelope = IntegrityEnvelope.fromJson(json)

        assertEquals(originalEnvelope, restoredEnvelope)
    }

    @Test
    fun `test fromJson with empty string throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson("")
        }
    }

    @Test
    fun `test fromJson with blank string throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson("   ")
        }
    }

    @Test
    fun `test fromJson with invalid JSON throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson("{invalid json}")
        }
    }

    @Test
    fun `test fromJson with missing data field throws exception`() {
        val invalidJson = """
            {
                "checksum":"$testChecksum",
                "algorithm":"SHA256",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with missing checksum field throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "algorithm":"SHA256",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with missing algorithm field throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "checksum":"$testChecksum",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with missing timestamp field throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "checksum":"$testChecksum",
                "algorithm":"SHA256"
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with invalid Base64 data throws exception`() {
        val invalidJson = """
            {
                "data":"invalid-base64!!!",
                "checksum":"$testChecksum",
                "algorithm":"SHA256",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with invalid algorithm throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "checksum":"$testChecksum",
                "algorithm":"INVALID_ALGORITHM",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with invalid timestamp throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "checksum":"$testChecksum",
                "algorithm":"SHA256",
                "timestamp":"not-a-number"
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            IntegrityEnvelope.fromJson(invalidJson)
        }
    }

    @Test
    fun `test equals with same content returns true`() {
        val envelope1 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)
        val envelope2 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)

        assertEquals(envelope1, envelope2)
    }

    @Test
    fun `test equals with different data returns false`() {
        val envelope1 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)
        val envelope2 = IntegrityEnvelope("Different".toByteArray(), testChecksum, testAlgorithm, testTimestamp)

        assertNotEquals(envelope1, envelope2)
    }

    @Test
    fun `test equals with different checksum returns false`() {
        val envelope1 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)
        val envelope2 = IntegrityEnvelope(testData, "different-checksum", testAlgorithm, testTimestamp)

        assertNotEquals(envelope1, envelope2)
    }

    @Test
    fun `test equals with different algorithm returns false`() {
        val envelope1 = IntegrityEnvelope(testData, testChecksum, ChecksumAlgorithm.SHA256, testTimestamp)
        val envelope2 = IntegrityEnvelope(testData, testChecksum, ChecksumAlgorithm.MD5, testTimestamp)

        assertNotEquals(envelope1, envelope2)
    }

    @Test
    fun `test equals with different timestamp returns false`() {
        val envelope1 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)
        val envelope2 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp + 1000)

        assertNotEquals(envelope1, envelope2)
    }

    @Test
    fun `test hashCode consistency`() {
        val envelope = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)
        val hash1 = envelope.hashCode()
        val hash2 = envelope.hashCode()

        assertEquals(hash1, hash2)
    }

    @Test
    fun `test hashCode with equal envelopes produces same hash`() {
        val envelope1 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)
        val envelope2 = IntegrityEnvelope(testData, testChecksum, testAlgorithm, testTimestamp)

        assertEquals(envelope1.hashCode(), envelope2.hashCode())
    }
}
