package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.security.SecureRandom
import java.util.UUID

/**
 * Object responsible for generating cryptographically secure random values.
 * Provides methods for generating random bytes, integers, longs, doubles, booleans, UUIDs, and shuffling lists.
 * Uses SecureRandom for all random number generation to ensure cryptographic strength.
 */
object SecureRandomGenerator {

    /**
     * Shared SecureRandom instance for generating cryptographically secure random values.
     * Uses getInstanceStrong() to ensure the strongest available algorithm is used,
     * with a fallback to the default SecureRandom if strong instance is unavailable.
     */
    private val secureRandom: SecureRandom by lazy {
        try {
            SecureRandom.getInstanceStrong()
        } catch (e: Exception) {
            SecureRandom()
        }
    }

    /**
     * Generates a cryptographically secure random byte array of the specified length.
     *
     * @param length The length of the byte array to generate. Must be positive.
     * @return A byte array of the specified length filled with random bytes.
     * @throws CryptoOperationException if the length is less than or equal to 0.
     */
    @JvmStatic
    fun generateBytes(length: Int): ByteArray {
        if (length <= 0) {
            throw CryptoOperationException("Random byte generation failed: length must be positive")
        }

        return try {
            ByteArray(length).also { secureRandom.nextBytes(it) }
        } catch (e: Exception) {
            throw CryptoOperationException("Random byte generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random integer.
     *
     * @return A random integer value.
     */
    @JvmStatic
    fun generateInt(): Int {
        return try {
            secureRandom.nextInt()
        } catch (e: Exception) {
            throw CryptoOperationException("Random int generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random integer between 0 (inclusive) and the specified bound (exclusive).
     *
     * @param bound The upper bound (exclusive). Must be positive.
     * @return A random integer value between 0 (inclusive) and bound (exclusive).
     * @throws CryptoOperationException if the bound is less than or equal to 0.
     */
    @JvmStatic
    fun generateInt(bound: Int): Int {
        if (bound <= 0) {
            throw CryptoOperationException("Random int generation failed: bound must be positive")
        }

        return try {
            secureRandom.nextInt(bound)
        } catch (e: Exception) {
            throw CryptoOperationException("Random int generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random integer between min (inclusive) and max (inclusive).
     *
     * @param min The minimum value (inclusive).
     * @param max The maximum value (inclusive).
     * @return A random integer value between min and max (both inclusive).
     * @throws CryptoOperationException if min is greater than max.
     */
    @JvmStatic
    fun generateInt(min: Int, max: Int): Int {
        if (min > max) {
            throw CryptoOperationException("Random int generation failed: min must be less than or equal to max")
        }

        if (min == max) {
            return min
        }

        return try {
            // Calculate the range and add min to the result
            val range = max.toLong() - min.toLong() + 1
            min + secureRandom.nextInt(range.toInt())
        } catch (e: Exception) {
            throw CryptoOperationException("Random int generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random long value.
     *
     * @return A random long value.
     */
    @JvmStatic
    fun generateLong(): Long {
        return try {
            secureRandom.nextLong()
        } catch (e: Exception) {
            throw CryptoOperationException("Random long generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random long value between min (inclusive) and max (inclusive).
     *
     * @param min The minimum value (inclusive).
     * @param max The maximum value (inclusive).
     * @return A random long value between min and max (both inclusive).
     * @throws CryptoOperationException if min is greater than max.
     */
    @JvmStatic
    fun generateLong(min: Long, max: Long): Long {
        if (min > max) {
            throw CryptoOperationException("Random long generation failed: min must be less than or equal to max")
        }

        if (min == max) {
            return min
        }

        return try {
            // Calculate the range
            val range = max - min + 1

            // For positive ranges that fit in Long
            if (range > 0) {
                var result: Long
                do {
                    result = secureRandom.nextLong() and Long.MAX_VALUE
                } while (result >= range)
                return min + result
            } else {
                // Handle the full Long range
                secureRandom.nextLong()
            }
        } catch (e: Exception) {
            throw CryptoOperationException("Random long generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random double value between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return A random double value between 0.0 and 1.0.
     */
    @JvmStatic
    fun generateDouble(): Double {
        return try {
            secureRandom.nextDouble()
        } catch (e: Exception) {
            throw CryptoOperationException("Random double generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random boolean value.
     *
     * @return A random boolean value (true or false).
     */
    @JvmStatic
    fun generateBoolean(): Boolean {
        return try {
            secureRandom.nextBoolean()
        } catch (e: Exception) {
            throw CryptoOperationException("Random boolean generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure random UUID (Universally Unique Identifier).
     * Uses random UUID version 4 based on SecureRandom.
     *
     * @return A random UUID string in the format "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".
     */
    @JvmStatic
    fun generateUUID(): String {
        return try {
            // Generate 16 random bytes
            val randomBytes = ByteArray(16)
            secureRandom.nextBytes(randomBytes)

            // Set version to 4 (random UUID)
            randomBytes[6] = (randomBytes[6].toInt() and 0x0f or 0x40).toByte()

            // Set variant to RFC 4122
            randomBytes[8] = (randomBytes[8].toInt() and 0x3f or 0x80).toByte()

            // Convert to UUID
            val msb = randomBytes.copyOfRange(0, 8).fold(0L) { acc, byte ->
                (acc shl 8) or (byte.toLong() and 0xff)
            }
            val lsb = randomBytes.copyOfRange(8, 16).fold(0L) { acc, byte ->
                (acc shl 8) or (byte.toLong() and 0xff)
            }

            UUID(msb, lsb).toString()
        } catch (e: Exception) {
            throw CryptoOperationException("Random UUID generation failed", e)
        }
    }

    /**
     * Shuffles a mutable list using a cryptographically secure random algorithm.
     * Uses the Fisher-Yates shuffle algorithm with SecureRandom.
     *
     * @param list The mutable list to shuffle.
     * @return The shuffled list (same instance as input).
     */
    @JvmStatic
    fun <T> shuffle(list: MutableList<T>): MutableList<T> {
        return try {
            // Fisher-Yates shuffle algorithm
            for (i in list.size - 1 downTo 1) {
                val j = secureRandom.nextInt(i + 1)
                val temp = list[i]
                list[i] = list[j]
                list[j] = temp
            }
            list
        } catch (e: Exception) {
            throw CryptoOperationException("Random shuffle failed", e)
        }
    }
}
