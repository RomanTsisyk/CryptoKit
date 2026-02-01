package io.github.romantsisyk.cryptolib.integrity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ChecksumAlgorithmTest {

    @Test
    fun `test algorithm names match expected values`() {
        assertEquals("CRC32", ChecksumAlgorithm.CRC32.algorithmName)
        assertEquals("ADLER32", ChecksumAlgorithm.ADLER32.algorithmName)
        assertEquals("MD5", ChecksumAlgorithm.MD5.algorithmName)
        assertEquals("SHA-256", ChecksumAlgorithm.SHA256.algorithmName)
        assertEquals("SHA-512", ChecksumAlgorithm.SHA512.algorithmName)
    }

    @Test
    fun `test default algorithm is SHA256`() {
        assertEquals(ChecksumAlgorithm.SHA256, ChecksumAlgorithm.default())
    }

    @Test
    fun `test fromString with valid algorithm names`() {
        assertEquals(ChecksumAlgorithm.CRC32, ChecksumAlgorithm.fromString("CRC32"))
        assertEquals(ChecksumAlgorithm.ADLER32, ChecksumAlgorithm.fromString("ADLER32"))
        assertEquals(ChecksumAlgorithm.MD5, ChecksumAlgorithm.fromString("MD5"))
        assertEquals(ChecksumAlgorithm.SHA256, ChecksumAlgorithm.fromString("SHA-256"))
        assertEquals(ChecksumAlgorithm.SHA512, ChecksumAlgorithm.fromString("SHA-512"))
    }

    @Test
    fun `test fromString is case insensitive`() {
        assertEquals(ChecksumAlgorithm.SHA256, ChecksumAlgorithm.fromString("sha-256"))
        assertEquals(ChecksumAlgorithm.MD5, ChecksumAlgorithm.fromString("md5"))
        assertEquals(ChecksumAlgorithm.CRC32, ChecksumAlgorithm.fromString("crc32"))
    }

    @Test
    fun `test fromString returns null for invalid algorithm`() {
        assertNull(ChecksumAlgorithm.fromString("INVALID"))
        assertNull(ChecksumAlgorithm.fromString("SHA-1"))
        assertNull(ChecksumAlgorithm.fromString(""))
    }

    @Test
    fun `test all enum values are accessible`() {
        val algorithms = ChecksumAlgorithm.entries
        assertEquals(5, algorithms.size)

        assertNotNull(algorithms.find { it == ChecksumAlgorithm.CRC32 })
        assertNotNull(algorithms.find { it == ChecksumAlgorithm.ADLER32 })
        assertNotNull(algorithms.find { it == ChecksumAlgorithm.MD5 })
        assertNotNull(algorithms.find { it == ChecksumAlgorithm.SHA256 })
        assertNotNull(algorithms.find { it == ChecksumAlgorithm.SHA512 })
    }
}
