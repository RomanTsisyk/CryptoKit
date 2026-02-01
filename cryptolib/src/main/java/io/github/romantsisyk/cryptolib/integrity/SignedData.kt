package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.util.Base64

/**
 * Data class representing digitally signed data.
 *
 * This class encapsulates the original data along with its digital signature
 * and metadata about the signing operation, including the signature algorithm
 * and timestamp.
 *
 * @property data The original data as a byte array.
 * @property signature The digital signature as a byte array.
 * @property signatureAlgorithm The algorithm used to create the signature (e.g., "SHA256withRSA").
 * @property timestamp The Unix timestamp (milliseconds) when the data was signed.
 */
data class SignedData(
    val data: ByteArray,
    val signature: ByteArray,
    val signatureAlgorithm: String,
    val timestamp: Long
) {
    /**
     * Converts this signed data to a JSON string representation.
     *
     * The JSON format is:
     * {
     *   "data": "base64-encoded-data",
     *   "signature": "base64-encoded-signature",
     *   "signatureAlgorithm": "algorithm-name",
     *   "timestamp": 123456789
     * }
     *
     * @return A JSON string representation of this signed data.
     */
    fun toJson(): String {
        val base64Data = Base64.getEncoder().encodeToString(data)
        val base64Signature = Base64.getEncoder().encodeToString(signature)
        return buildString {
            append("{")
            append("\"data\":\"$base64Data\",")
            append("\"signature\":\"$base64Signature\",")
            append("\"signatureAlgorithm\":\"$signatureAlgorithm\",")
            append("\"timestamp\":$timestamp")
            append("}")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignedData

        if (!data.contentEquals(other.data)) return false
        if (!signature.contentEquals(other.signature)) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (timestamp != other.timestamp) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }

    companion object {
        /**
         * Creates a SignedData instance from a JSON string representation.
         *
         * @param json The JSON string to parse.
         * @return A SignedData instance created from the JSON data.
         * @throws CryptoOperationException if the JSON is invalid or cannot be parsed.
         */
        @JvmStatic
        fun fromJson(json: String): SignedData {
            if (json.isBlank()) {
                throw CryptoOperationException("Cannot parse SignedData: JSON string is empty")
            }

            return try {
                val dataValue = extractJsonValue(json, "data")
                val signatureValue = extractJsonValue(json, "signature")
                val algorithmValue = extractJsonValue(json, "signatureAlgorithm")
                val timestampValue = extractJsonValue(json, "timestamp")

                val data = Base64.getDecoder().decode(dataValue)
                val signature = Base64.getDecoder().decode(signatureValue)
                val timestamp = timestampValue.toLong()

                SignedData(
                    data = data,
                    signature = signature,
                    signatureAlgorithm = algorithmValue,
                    timestamp = timestamp
                )
            } catch (e: IllegalArgumentException) {
                throw CryptoOperationException("Failed to parse SignedData from JSON: invalid data format", e)
            } catch (e: Exception) {
                throw CryptoOperationException("Failed to parse SignedData from JSON", e)
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
