package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64

/**
 * High-level manager for data integrity operations.
 *
 * This object provides comprehensive data integrity management, including:
 * - Creating integrity envelopes with checksums and timestamps
 * - Verifying data integrity through checksum validation
 * - Digitally signing data for authenticity verification
 * - Verifying digital signatures
 *
 * The manager integrates checksum-based integrity verification with
 * cryptographic digital signatures for comprehensive data protection.
 */
object DataIntegrityManager {

    /**
     * Creates an integrity envelope containing the data, its checksum, algorithm, and timestamp.
     *
     * The envelope provides a complete package for verifying data integrity at a later time,
     * including when the data was packaged and what algorithm was used.
     *
     * @param data The data to package in an integrity envelope.
     * @param algorithm The checksum algorithm to use (defaults to SHA256).
     * @return An IntegrityEnvelope containing the data and its integrity information.
     * @throws CryptoOperationException if envelope creation fails.
     */
    @JvmStatic
    @JvmOverloads
    fun createIntegrityEnvelope(
        data: ByteArray,
        algorithm: ChecksumAlgorithm = ChecksumAlgorithm.default()
    ): IntegrityEnvelope {
        if (data.isEmpty()) {
            throw CryptoOperationException("Cannot create integrity envelope: data is empty")
        }

        return try {
            val checksum = ChecksumUtils.calculateChecksum(data, algorithm)
            val timestamp = System.currentTimeMillis()

            IntegrityEnvelope(
                data = data,
                checksum = checksum,
                algorithm = algorithm,
                timestamp = timestamp
            )
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to create integrity envelope", e)
        }
    }

    /**
     * Verifies the integrity of an envelope by recalculating its checksum and comparing
     * it with the stored checksum.
     *
     * This method ensures that:
     * 1. The data has not been modified since the envelope was created
     * 2. The checksum was calculated correctly
     *
     * @param envelope The integrity envelope to verify.
     * @return True if the data integrity is valid, false otherwise.
     * @throws CryptoOperationException if verification fails due to an error.
     */
    @JvmStatic
    fun verifyIntegrity(envelope: IntegrityEnvelope): Boolean {
        return try {
            ChecksumUtils.verifyChecksum(
                data = envelope.data,
                expectedChecksum = envelope.checksum,
                algorithm = envelope.algorithm
            )
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to verify integrity envelope", e)
        }
    }

    /**
     * Creates a digitally signed data package containing the data, signature,
     * algorithm information, and timestamp.
     *
     * Digital signatures provide:
     * - Authenticity: Proof that the data came from the holder of the private key
     * - Integrity: Assurance that the data has not been modified
     * - Non-repudiation: The signer cannot deny having signed the data
     *
     * @param data The data to sign.
     * @param privateKey The private key used for signing.
     * @return A SignedData object containing the data and its signature.
     * @throws CryptoOperationException if signing fails.
     */
    @JvmStatic
    fun signData(data: ByteArray, privateKey: PrivateKey): SignedData {
        if (data.isEmpty()) {
            throw CryptoOperationException("Cannot sign data: data is empty")
        }

        return try {
            val signatureBase64 = DigitalSignature.sign(data, privateKey)
            val signatureBytes = Base64.getDecoder().decode(signatureBase64)
            val timestamp = System.currentTimeMillis()

            // Determine the signature algorithm based on the key type
            val signatureAlgorithm = when (privateKey.algorithm) {
                "RSA" -> "SHA256withRSA/PSS"
                "EC" -> "SHA256withECDSA"
                else -> throw CryptoOperationException("Unsupported key algorithm: ${privateKey.algorithm}")
            }

            SignedData(
                data = data,
                signature = signatureBytes,
                signatureAlgorithm = signatureAlgorithm,
                timestamp = timestamp
            )
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to sign data", e)
        }
    }

    /**
     * Verifies a digital signature using the provided public key.
     *
     * This method validates that:
     * 1. The signature was created using the corresponding private key
     * 2. The data has not been modified since it was signed
     *
     * @param signedData The signed data to verify.
     * @param publicKey The public key corresponding to the private key used for signing.
     * @return True if the signature is valid, false otherwise.
     * @throws CryptoOperationException if verification fails due to an error.
     */
    @JvmStatic
    fun verifySignature(signedData: SignedData, publicKey: PublicKey): Boolean {
        return try {
            val signatureBase64 = Base64.getEncoder().encodeToString(signedData.signature)
            DigitalSignature.verify(signedData.data, signatureBase64, publicKey)
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to verify signature", e)
        }
    }

    /**
     * Creates a combined integrity envelope with digital signature.
     *
     * This method provides the highest level of data protection by combining:
     * - Checksum-based integrity verification
     * - Digital signature for authenticity
     * - Timestamp information
     *
     * @param data The data to protect.
     * @param privateKey The private key for signing.
     * @param algorithm The checksum algorithm to use (defaults to SHA256).
     * @return A pair containing the IntegrityEnvelope and SignedData.
     * @throws CryptoOperationException if creation fails.
     */
    @JvmStatic
    @JvmOverloads
    fun createSignedEnvelope(
        data: ByteArray,
        privateKey: PrivateKey,
        algorithm: ChecksumAlgorithm = ChecksumAlgorithm.default()
    ): Pair<IntegrityEnvelope, SignedData> {
        val envelope = createIntegrityEnvelope(data, algorithm)
        val signedData = signData(data, privateKey)
        return Pair(envelope, signedData)
    }

    /**
     * Verifies both the integrity envelope and digital signature.
     *
     * @param envelope The integrity envelope to verify.
     * @param signedData The signed data to verify.
     * @param publicKey The public key for signature verification.
     * @return True if both integrity check and signature verification pass, false otherwise.
     * @throws CryptoOperationException if verification fails due to an error.
     */
    @JvmStatic
    fun verifySignedEnvelope(
        envelope: IntegrityEnvelope,
        signedData: SignedData,
        publicKey: PublicKey
    ): Boolean {
        // Verify that the envelope and signed data contain the same data
        if (!envelope.data.contentEquals(signedData.data)) {
            return false
        }

        val integrityValid = verifyIntegrity(envelope)
        val signatureValid = verifySignature(signedData, publicKey)

        return integrityValid && signatureValid
    }
}
