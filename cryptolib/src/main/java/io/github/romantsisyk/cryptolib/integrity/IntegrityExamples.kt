package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature
import java.io.File

/**
 * Example usage patterns for the Data Integrity module.
 *
 * This file demonstrates common use cases and best practices for using
 * the integrity module components.
 */
object IntegrityExamples {

    /**
     * Example 1: Basic checksum calculation and verification
     */
    fun basicChecksumExample() {
        // Calculate checksum
        val data = "Important data to protect".toByteArray()
        val checksum = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.SHA256)
        println("Checksum: $checksum")

        // Verify data integrity
        val isValid = ChecksumUtils.verifyChecksum(data, checksum, ChecksumAlgorithm.SHA256)
        println("Data integrity: ${if (isValid) "Valid" else "Invalid"}")
    }

    /**
     * Example 2: File integrity verification
     */
    fun fileIntegrityExample(file: File) {
        // Calculate file checksum for distribution
        val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
        println("Distribute this checksum with your file: $checksum")

        // Later, verify the file hasn't been modified
        val isUnmodified = ChecksumUtils.verifyChecksum(file, checksum, ChecksumAlgorithm.SHA256)
        if (isUnmodified) {
            println("File is intact and unmodified")
        } else {
            println("WARNING: File has been modified or corrupted!")
        }
    }

    /**
     * Example 3: Creating and verifying integrity envelopes
     */
    fun integrityEnvelopeExample() {
        // Sender creates an envelope
        val data = "Sensitive information".toByteArray()
        val envelope = DataIntegrityManager.createIntegrityEnvelope(data)

        // Serialize for storage or transmission
        val json = envelope.toJson()
        println("Envelope JSON: $json")

        // Later or on receiver side, deserialize and verify
        val receivedEnvelope = IntegrityEnvelope.fromJson(json)
        val isValid = DataIntegrityManager.verifyIntegrity(receivedEnvelope)

        if (isValid) {
            println("Data verified: ${String(receivedEnvelope.data)}")
        } else {
            println("Data integrity check failed!")
        }
    }

    /**
     * Example 4: Digital signatures for authentication
     */
    fun digitalSignatureExample() {
        // Generate key pair (do this once, store securely)
        val keyPair = DigitalSignature.generateKeyPair("RSA")

        // Sign data
        val data = "Message to be authenticated".toByteArray()
        val signedData = DataIntegrityManager.signData(data, keyPair.private)

        // Serialize for transmission
        val json = signedData.toJson()

        // Receiver verifies signature
        val receivedData = SignedData.fromJson(json)
        val isAuthentic = DataIntegrityManager.verifySignature(receivedData, keyPair.public)

        if (isAuthentic) {
            println("Signature verified - data is authentic!")
            println("Message: ${String(receivedData.data)}")
        } else {
            println("Signature verification failed - possible forgery!")
        }
    }

    /**
     * Example 5: Maximum security with combined protection
     */
    fun combinedProtectionExample() {
        // Generate key pair
        val keyPair = DigitalSignature.generateKeyPair("RSA")

        // Sender creates signed envelope
        val criticalData = "Highly sensitive information".toByteArray()
        val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
            data = criticalData,
            privateKey = keyPair.private,
            algorithm = ChecksumAlgorithm.SHA256
        )

        // Serialize both components
        val envelopeJson = envelope.toJson()
        val signatureJson = signedData.toJson()

        // Receiver verifies both integrity and authenticity
        val receivedEnvelope = IntegrityEnvelope.fromJson(envelopeJson)
        val receivedSignature = SignedData.fromJson(signatureJson)

        val isValid = DataIntegrityManager.verifySignedEnvelope(
            envelope = receivedEnvelope,
            signedData = receivedSignature,
            publicKey = keyPair.public
        )

        if (isValid) {
            println("Both integrity and authenticity verified!")
            println("Data: ${String(receivedEnvelope.data)}")
            println("Signed at: ${receivedSignature.timestamp}")
        } else {
            println("Verification failed!")
        }
    }

    /**
     * Example 6: Using different checksum algorithms
     */
    fun algorithmComparisonExample() {
        val data = "Test data".toByteArray()

        // Fast, non-cryptographic checksums
        val crc32 = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.CRC32)
        println("CRC32: $crc32 (8 hex chars)")

        val adler32 = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.ADLER32)
        println("ADLER32: $adler32 (8 hex chars)")

        // Cryptographic hashes
        val md5 = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.MD5)
        println("MD5: $md5 (32 hex chars)")

        val sha256 = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.SHA256)
        println("SHA256: $sha256 (64 hex chars)")

        val sha512 = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.SHA512)
        println("SHA512: $sha512 (128 hex chars)")
    }

    /**
     * Example 7: Stream processing for large files
     */
    fun streamProcessingExample(file: File) {
        // Use input stream for memory-efficient processing of large files
        file.inputStream().use { stream ->
            val checksum = ChecksumUtils.calculateChecksum(stream, ChecksumAlgorithm.SHA256)
            println("Large file checksum: $checksum")
        }
    }

    /**
     * Example 8: Detecting tampering
     */
    fun tamperDetectionExample() {
        // Original data
        val originalData = "Original message".toByteArray()
        val envelope = DataIntegrityManager.createIntegrityEnvelope(originalData)

        // Verify original
        println("Original data valid: ${DataIntegrityManager.verifyIntegrity(envelope)}")

        // Simulate tampering
        val tamperedEnvelope = IntegrityEnvelope(
            data = "Tampered message".toByteArray(),
            checksum = envelope.checksum, // Same checksum but different data
            algorithm = envelope.algorithm,
            timestamp = envelope.timestamp
        )

        // Verify tampered data
        val isValid = DataIntegrityManager.verifyIntegrity(tamperedEnvelope)
        println("Tampered data valid: $isValid") // Will be false
    }

    /**
     * Example 9: Using ECDSA for signatures
     */
    fun ecdsaSignatureExample() {
        // ECDSA is more efficient than RSA with smaller key sizes
        val ecKeyPair = DigitalSignature.generateKeyPair("EC")

        val data = "Message".toByteArray()
        val signedData = DataIntegrityManager.signData(data, ecKeyPair.private)

        println("Algorithm: ${signedData.signatureAlgorithm}") // SHA256withECDSA

        val isValid = DataIntegrityManager.verifySignature(signedData, ecKeyPair.public)
        println("ECDSA signature valid: $isValid")
    }

    /**
     * Example 10: Envelope with timestamp validation
     */
    fun timestampValidationExample() {
        val data = "Time-sensitive data".toByteArray()
        val envelope = DataIntegrityManager.createIntegrityEnvelope(data)

        // Check envelope age
        val age = System.currentTimeMillis() - envelope.timestamp
        val ageInMinutes = age / (1000 * 60)

        println("Envelope created $ageInMinutes minutes ago")

        // Verify integrity and timestamp freshness
        if (DataIntegrityManager.verifyIntegrity(envelope)) {
            if (ageInMinutes < 60) { // Less than 1 hour old
                println("Data is valid and fresh")
            } else {
                println("Data is valid but stale")
            }
        }
    }
}
