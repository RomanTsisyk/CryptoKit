package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SignedDataTest {

    private val testData = "Hello, World!".toByteArray()
    private val testSignature = "test-signature-bytes".toByteArray()
    private val testAlgorithm = "SHA256withRSA/PSS"
    private val testTimestamp = System.currentTimeMillis()

    @Test
    fun `test SignedData creation`() {
        val signedData = SignedData(
            data = testData,
            signature = testSignature,
            signatureAlgorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        assertArrayEquals(testData, signedData.data)
        assertArrayEquals(testSignature, signedData.signature)
        assertEquals(testAlgorithm, signedData.signatureAlgorithm)
        assertEquals(testTimestamp, signedData.timestamp)
    }

    @Test
    fun `test toJson creates valid JSON string`() {
        val signedData = SignedData(
            data = testData,
            signature = testSignature,
            signatureAlgorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        val json = signedData.toJson()

        assertTrue(json.contains("\"data\":"))
        assertTrue(json.contains("\"signature\":"))
        assertTrue(json.contains("\"signatureAlgorithm\":\"$testAlgorithm\""))
        assertTrue(json.contains("\"timestamp\":$testTimestamp"))
    }

    @Test
    fun `test fromJson creates SignedData from valid JSON`() {
        val signedData = SignedData(
            data = testData,
            signature = testSignature,
            signatureAlgorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        val json = signedData.toJson()
        val parsedSignedData = SignedData.fromJson(json)

        assertArrayEquals(signedData.data, parsedSignedData.data)
        assertArrayEquals(signedData.signature, parsedSignedData.signature)
        assertEquals(signedData.signatureAlgorithm, parsedSignedData.signatureAlgorithm)
        assertEquals(signedData.timestamp, parsedSignedData.timestamp)
    }

    @Test
    fun `test toJson and fromJson round trip preserves data`() {
        val originalSignedData = SignedData(
            data = testData,
            signature = testSignature,
            signatureAlgorithm = testAlgorithm,
            timestamp = testTimestamp
        )

        val json = originalSignedData.toJson()
        val restoredSignedData = SignedData.fromJson(json)

        assertEquals(originalSignedData, restoredSignedData)
    }

    @Test
    fun `test fromJson with empty string throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson("")
        }
    }

    @Test
    fun `test fromJson with blank string throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson("   ")
        }
    }

    @Test
    fun `test fromJson with invalid JSON throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson("{invalid json}")
        }
    }

    @Test
    fun `test fromJson with missing data field throws exception`() {
        val invalidJson = """
            {
                "signature":"dGVzdC1zaWduYXR1cmUtYnl0ZXM=",
                "signatureAlgorithm":"$testAlgorithm",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with missing signature field throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "signatureAlgorithm":"$testAlgorithm",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with missing signatureAlgorithm field throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "signature":"dGVzdC1zaWduYXR1cmUtYnl0ZXM=",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with missing timestamp field throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "signature":"dGVzdC1zaWduYXR1cmUtYnl0ZXM=",
                "signatureAlgorithm":"$testAlgorithm"
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with invalid Base64 data throws exception`() {
        val invalidJson = """
            {
                "data":"invalid-base64!!!",
                "signature":"dGVzdC1zaWduYXR1cmUtYnl0ZXM=",
                "signatureAlgorithm":"$testAlgorithm",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with invalid Base64 signature throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "signature":"invalid-base64!!!",
                "signatureAlgorithm":"$testAlgorithm",
                "timestamp":$testTimestamp
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test fromJson with invalid timestamp throws exception`() {
        val invalidJson = """
            {
                "data":"SGVsbG8sIFdvcmxkIQ==",
                "signature":"dGVzdC1zaWduYXR1cmUtYnl0ZXM=",
                "signatureAlgorithm":"$testAlgorithm",
                "timestamp":"not-a-number"
            }
        """.trimIndent()

        assertThrows(CryptoOperationException::class.java) {
            SignedData.fromJson(invalidJson)
        }
    }

    @Test
    fun `test equals with same content returns true`() {
        val signedData1 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)
        val signedData2 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)

        assertEquals(signedData1, signedData2)
    }

    @Test
    fun `test equals with different data returns false`() {
        val signedData1 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)
        val signedData2 = SignedData("Different".toByteArray(), testSignature, testAlgorithm, testTimestamp)

        assertNotEquals(signedData1, signedData2)
    }

    @Test
    fun `test equals with different signature returns false`() {
        val signedData1 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)
        val signedData2 = SignedData(testData, "different".toByteArray(), testAlgorithm, testTimestamp)

        assertNotEquals(signedData1, signedData2)
    }

    @Test
    fun `test equals with different algorithm returns false`() {
        val signedData1 = SignedData(testData, testSignature, "SHA256withRSA/PSS", testTimestamp)
        val signedData2 = SignedData(testData, testSignature, "SHA256withECDSA", testTimestamp)

        assertNotEquals(signedData1, signedData2)
    }

    @Test
    fun `test equals with different timestamp returns false`() {
        val signedData1 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)
        val signedData2 = SignedData(testData, testSignature, testAlgorithm, testTimestamp + 1000)

        assertNotEquals(signedData1, signedData2)
    }

    @Test
    fun `test hashCode consistency`() {
        val signedData = SignedData(testData, testSignature, testAlgorithm, testTimestamp)
        val hash1 = signedData.hashCode()
        val hash2 = signedData.hashCode()

        assertEquals(hash1, hash2)
    }

    @Test
    fun `test hashCode with equal SignedData produces same hash`() {
        val signedData1 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)
        val signedData2 = SignedData(testData, testSignature, testAlgorithm, testTimestamp)

        assertEquals(signedData1.hashCode(), signedData2.hashCode())
    }

    @Test
    fun `test SignedData with ECDSA algorithm`() {
        val ecdsaAlgorithm = "SHA256withECDSA"
        val signedData = SignedData(
            data = testData,
            signature = testSignature,
            signatureAlgorithm = ecdsaAlgorithm,
            timestamp = testTimestamp
        )

        assertEquals(ecdsaAlgorithm, signedData.signatureAlgorithm)

        // Test JSON serialization/deserialization
        val json = signedData.toJson()
        val restored = SignedData.fromJson(json)
        assertEquals(signedData, restored)
    }
}
