package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Utility object for handling PEM (Privacy-Enhanced Mail) format encoding and decoding
 * of cryptographic keys and certificates.
 * PEM format is widely used for storing and transmitting cryptographic keys.
 */
object PEMUtils {

    private const val PEM_LINE_LENGTH = 64
    private const val PEM_PREFIX = "-----BEGIN "
    private const val PEM_SUFFIX = "-----END "
    private const val PEM_POSTFIX = "-----"

    /**
     * Encodes a public key to PEM format.
     *
     * @param key The public key to encode.
     * @param type The key type label (defaults to "PUBLIC KEY").
     * @return A PEM-formatted string representation of the key.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    @JvmOverloads
    fun encodeToPEM(key: PublicKey, type: String = "PUBLIC KEY"): String {
        return try {
            val encoded = key.encoded
            encodeToPEMFormat(encoded, type)
        } catch (e: Exception) {
            throw CryptoOperationException("Public key PEM encoding failed: ${e.message}", e)
        }
    }

    /**
     * Encodes a private key to PEM format.
     *
     * @param key The private key to encode.
     * @param type The key type label (defaults to "PRIVATE KEY").
     * @return A PEM-formatted string representation of the key.
     * @throws CryptoOperationException if encoding fails.
     */
    @JvmStatic
    @JvmOverloads
    fun encodeToPEM(key: PrivateKey, type: String = "PRIVATE KEY"): String {
        return try {
            val encoded = key.encoded
            encodeToPEMFormat(encoded, type)
        } catch (e: Exception) {
            throw CryptoOperationException("Private key PEM encoding failed: ${e.message}", e)
        }
    }

    /**
     * Decodes a PEM-formatted string to a public key.
     *
     * @param pem The PEM-formatted string containing the public key.
     * @return The decoded PublicKey object.
     * @throws CryptoOperationException if the PEM format is invalid or decoding fails.
     */
    @JvmStatic
    fun decodePublicKeyFromPEM(pem: String): PublicKey {
        return try {
            val keyBytes = decodePEMContent(pem)
            val keySpec = X509EncodedKeySpec(keyBytes)

            // Try to determine the algorithm from the key data
            val algorithm = determineKeyAlgorithm(pem, "RSA")
            val keyFactory = KeyFactory.getInstance(algorithm)
            keyFactory.generatePublic(keySpec)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Public key PEM decoding failed: ${e.message}", e)
        }
    }

    /**
     * Decodes a PEM-formatted string to a private key.
     *
     * @param pem The PEM-formatted string containing the private key.
     * @param algorithm The key algorithm to use (defaults to "RSA").
     * @return The decoded PrivateKey object.
     * @throws CryptoOperationException if the PEM format is invalid or decoding fails.
     */
    @JvmStatic
    @JvmOverloads
    fun decodePrivateKeyFromPEM(pem: String, algorithm: String = "RSA"): PrivateKey {
        return try {
            val keyBytes = decodePEMContent(pem)
            val keySpec = PKCS8EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance(algorithm)
            keyFactory.generatePrivate(keySpec)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Private key PEM decoding failed: ${e.message}", e)
        }
    }

    /**
     * Validates whether the provided string is in PEM format.
     *
     * @param input The string to validate.
     * @return True if the input appears to be valid PEM format, false otherwise.
     */
    @JvmStatic
    fun isPEMFormat(input: String): Boolean {
        if (input.isBlank()) {
            return false
        }

        val trimmed = input.trim()
        return trimmed.startsWith(PEM_PREFIX) &&
               trimmed.contains(PEM_SUFFIX) &&
               trimmed.contains(PEM_POSTFIX)
    }

    /**
     * Helper function to encode byte array to PEM format with specified type.
     */
    private fun encodeToPEMFormat(data: ByteArray, type: String): String {
        val base64 = Base64.getEncoder().encodeToString(data)
        val builder = StringBuilder()

        // Add header
        builder.append(PEM_PREFIX).append(type).append(PEM_POSTFIX).append("\n")

        // Add base64 content with line breaks every 64 characters
        var offset = 0
        while (offset < base64.length) {
            val end = minOf(offset + PEM_LINE_LENGTH, base64.length)
            builder.append(base64.substring(offset, end)).append("\n")
            offset = end
        }

        // Add footer
        builder.append(PEM_SUFFIX).append(type).append(PEM_POSTFIX)

        return builder.toString()
    }

    /**
     * Helper function to decode PEM content to byte array.
     */
    private fun decodePEMContent(pem: String): ByteArray {
        if (!isPEMFormat(pem)) {
            throw CryptoOperationException("Invalid PEM format: missing PEM headers/footers")
        }

        try {
            // Remove header, footer, and whitespace
            val content = pem
                .lines()
                .filter { !it.startsWith(PEM_PREFIX) && !it.startsWith(PEM_SUFFIX) }
                .joinToString("")
                .trim()

            if (content.isEmpty()) {
                throw CryptoOperationException("Invalid PEM format: no content found")
            }

            return Base64.getDecoder().decode(content)
        } catch (e: IllegalArgumentException) {
            throw CryptoOperationException("Invalid PEM format: invalid Base64 content", e)
        }
    }

    /**
     * Helper function to determine the key algorithm from PEM header.
     */
    private fun determineKeyAlgorithm(pem: String, default: String): String {
        return when {
            pem.contains("RSA") -> "RSA"
            pem.contains("EC") -> "EC"
            pem.contains("DSA") -> "DSA"
            else -> default
        }
    }
}
