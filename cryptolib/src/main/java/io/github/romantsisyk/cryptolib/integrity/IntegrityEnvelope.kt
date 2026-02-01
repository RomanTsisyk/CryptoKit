package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64

/**
 * Data class representing an integrity envelope that contains data along with its checksum,
 * algorithm information, and timestamp for verification purposes.
 *
 * This envelope provides a complete package for verifying data integrity, including:
 * - The original data
 * - A checksum calculated using a specified algorithm
 * - The algorithm used for checksum calculation
 * - A timestamp indicating when the envelope was created
 *
 * @property data The original data as a byte array.
 * @property checksum The hexadecimal string representation of the data's checksum.
 * @property algorithm The algorithm used to calculate the checksum.
 * @property timestamp The Unix timestamp (milliseconds) when the envelope was created.
 */
data class IntegrityEnvelope(
    val data: ByteArray,
    val checksum: String,
    val algorithm: ChecksumAlgorithm,
    val timestamp: Long
) {
    /**
     * Converts this integrity envelope to a JSON string representation.
     *
     * The JSON format is:
     * {
     *   "data": "base64-encoded-data",
     *   "checksum": "hex-checksum",
     *   "algorithm": "ALGORITHM_NAME",
     *   "timestamp": 123456789
     * }
     *
     * @return A JSON string representation of this envelope.
     */
    fun toJson(): String {
        val base64Data = Base64.getEncoder().encodeToString(data)
        return buildString {
            append("{")
            append("\"data\":\"$base64Data\",")
            append("\"checksum\":\"$checksum\",")
            append("\"algorithm\":\"${algorithm.name}\",")
            append("\"timestamp\":$timestamp")
            append("}")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IntegrityEnvelope

        if (!data.contentEquals(other.data)) return false
        if (checksum != other.checksum) return false
        if (algorithm != other.algorithm) return false
        if (timestamp != other.timestamp) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + checksum.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }

    companion object {
        /**
         * Creates an IntegrityEnvelope from a JSON string representation.
         *
         * @param json The JSON string to parse.
         * @return An IntegrityEnvelope instance created from the JSON data.
         * @throws CryptoOperationException if the JSON is invalid or cannot be parsed.
         */
        @JvmStatic
        fun fromJson(json: String): IntegrityEnvelope {
            if (json.isBlank()) {
                throw CryptoOperationException("Cannot parse IntegrityEnvelope: JSON string is empty")
            }

            return try {
                val dataValue = extractJsonValue(json, "data")
                val checksumValue = extractJsonValue(json, "checksum")
                val algorithmValue = extractJsonValue(json, "algorithm")
                val timestampValue = extractJsonValue(json, "timestamp")

                val data = Base64.getDecoder().decode(dataValue)
                val algorithm = ChecksumAlgorithm.valueOf(algorithmValue)
                val timestamp = timestampValue.toLong()

                IntegrityEnvelope(
                    data = data,
                    checksum = checksumValue,
                    algorithm = algorithm,
                    timestamp = timestamp
                )
            } catch (e: IllegalArgumentException) {
                throw CryptoOperationException("Failed to parse IntegrityEnvelope from JSON: invalid data format", e)
            } catch (e: Exception) {
                throw CryptoOperationException("Failed to parse IntegrityEnvelope from JSON", e)
            }
        }

        /**
         * Extracts a value for a given key from a simple JSON string.
         * This is a basic JSON parser for simple key-value pairs.
         *
         * @param json The JSON string.
         * @param key The key to extract.
         * @return The value associated with the key.
         * @throws CryptoOperationException if the key is not found.
         */
        private fun extractJsonValue(json: String, key: String): String {
            // Pattern: "key":"value" or "key":value (for numbers)
            val pattern = "\"$key\"\\s*:\\s*\"?([^,}\"]+)\"?".toRegex()
            val matchResult = pattern.find(json)
                ?: throw CryptoOperationException("JSON parsing failed: key '$key' not found")

            return matchResult.groupValues[1].trim()
        }
    }
}
