package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureRandomGeneratorTest {

    @Test
    fun `test generateBytes returns correct length`() {
        val length = 32
        val result = SecureRandomGenerator.generateBytes(length)
        assertEquals(length, result.size)
    }

    @Test
    fun `test generateBytes produces different results on each call`() {
        val length = 32
        val result1 = SecureRandomGenerator.generateBytes(length)
        val result2 = SecureRandomGenerator.generateBytes(length)
        assertFalse(result1.contentEquals(result2))
    }

    @Test
    fun `test generateBytes throws exception for non-positive length`() {
        assertThrows(CryptoOperationException::class.java) {
            SecureRandomGenerator.generateBytes(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            SecureRandomGenerator.generateBytes(-1)
        }
    }

    @Test
    fun `test generateInt produces different results`() {
        val result1 = SecureRandomGenerator.generateInt()
        val result2 = SecureRandomGenerator.generateInt()
        // Very unlikely to be equal for random integers
        assertNotEquals(result1, result2)
    }

    @Test
    fun `test generateInt with bound returns value in range`() {
        val bound = 100
        repeat(100) {
            val result = SecureRandomGenerator.generateInt(bound)
            assertTrue(result >= 0)
            assertTrue(result < bound)
        }
    }

    @Test
    fun `test generateInt with bound throws exception for non-positive bound`() {
        assertThrows(CryptoOperationException::class.java) {
            SecureRandomGenerator.generateInt(0)
        }

        assertThrows(CryptoOperationException::class.java) {
            SecureRandomGenerator.generateInt(-1)
        }
    }

    @Test
    fun `test generateInt with min and max returns value in range`() {
        val min = 10
        val max = 50
        repeat(100) {
            val result = SecureRandomGenerator.generateInt(min, max)
            assertTrue(result >= min)
            assertTrue(result <= max)
        }
    }

    @Test
    fun `test generateInt with equal min and max returns same value`() {
        val value = 42
        val result = SecureRandomGenerator.generateInt(value, value)
        assertEquals(value, result)
    }

    @Test
    fun `test generateInt throws exception when min is greater than max`() {
        assertThrows(CryptoOperationException::class.java) {
            SecureRandomGenerator.generateInt(100, 50)
        }
    }

    @Test
    fun `test generateLong produces different results`() {
        val result1 = SecureRandomGenerator.generateLong()
        val result2 = SecureRandomGenerator.generateLong()
        // Very unlikely to be equal for random longs
        assertNotEquals(result1, result2)
    }

    @Test
    fun `test generateLong with min and max returns value in range`() {
        val min = 100L
        val max = 1000L
        repeat(100) {
            val result = SecureRandomGenerator.generateLong(min, max)
            assertTrue(result >= min)
            assertTrue(result <= max)
        }
    }

    @Test
    fun `test generateLong with equal min and max returns same value`() {
        val value = 42L
        val result = SecureRandomGenerator.generateLong(value, value)
        assertEquals(value, result)
    }

    @Test
    fun `test generateLong throws exception when min is greater than max`() {
        assertThrows(CryptoOperationException::class.java) {
            SecureRandomGenerator.generateLong(1000L, 100L)
        }
    }

    @Test
    fun `test generateDouble returns value between 0 and 1`() {
        repeat(100) {
            val result = SecureRandomGenerator.generateDouble()
            assertTrue(result >= 0.0)
            assertTrue(result < 1.0)
        }
    }

    @Test
    fun `test generateBoolean returns both true and false`() {
        val results = mutableSetOf<Boolean>()
        repeat(100) {
            results.add(SecureRandomGenerator.generateBoolean())
        }
        assertTrue(results.contains(true))
        assertTrue(results.contains(false))
    }

    @Test
    fun `test generateUUID produces valid UUID format`() {
        val uuid = SecureRandomGenerator.generateUUID()
        // UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        val uuidPattern = Regex(
            "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        assertTrue(uuid.matches(uuidPattern))
    }

    @Test
    fun `test generateUUID produces different UUIDs`() {
        val uuid1 = SecureRandomGenerator.generateUUID()
        val uuid2 = SecureRandomGenerator.generateUUID()
        assertNotEquals(uuid1, uuid2)
    }

    @Test
    fun `test shuffle randomizes list order`() {
        val original = (1..100).toMutableList()
        val copy = original.toMutableList()
        val shuffled = SecureRandomGenerator.shuffle(copy)

        // Shuffled list should contain the same elements
        assertEquals(original.sorted(), shuffled.sorted())

        // Shuffled list should not be in the same order (very unlikely)
        assertNotEquals(original, shuffled)
    }

    @Test
    fun `test shuffle preserves list elements`() {
        val original = listOf("apple", "banana", "cherry", "date", "elderberry")
        val mutableList = original.toMutableList()
        val shuffled = SecureRandomGenerator.shuffle(mutableList)

        assertEquals(original.size, shuffled.size)
        assertTrue(shuffled.containsAll(original))
    }

    @Test
    fun `test shuffle with empty list returns empty list`() {
        val emptyList = mutableListOf<Int>()
        val shuffled = SecureRandomGenerator.shuffle(emptyList)
        assertTrue(shuffled.isEmpty())
    }

    @Test
    fun `test shuffle with single element returns same element`() {
        val singleElementList = mutableListOf(42)
        val shuffled = SecureRandomGenerator.shuffle(singleElementList)
        assertEquals(1, shuffled.size)
        assertEquals(42, shuffled[0])
    }

    @Test
    fun `test generateBytes with large size`() {
        val largeSize = 10000
        val result = SecureRandomGenerator.generateBytes(largeSize)
        assertEquals(largeSize, result.size)
    }

    @Test
    fun `test generateInt with negative range`() {
        val min = -100
        val max = -10
        repeat(100) {
            val result = SecureRandomGenerator.generateInt(min, max)
            assertTrue(result >= min)
            assertTrue(result <= max)
        }
    }

    @Test
    fun `test generateInt with mixed sign range`() {
        val min = -50
        val max = 50
        repeat(100) {
            val result = SecureRandomGenerator.generateInt(min, max)
            assertTrue(result >= min)
            assertTrue(result <= max)
        }
    }

    @Test
    fun `test generateLong with negative range`() {
        val min = -1000L
        val max = -100L
        repeat(100) {
            val result = SecureRandomGenerator.generateLong(min, max)
            assertTrue(result >= min)
            assertTrue(result <= max)
        }
    }
}
