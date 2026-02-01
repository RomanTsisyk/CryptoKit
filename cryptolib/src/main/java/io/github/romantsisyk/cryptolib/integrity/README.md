# Data Integrity Module

## Overview

The Data Integrity module provides comprehensive functionality for data validation, checksums, and digital signatures. This module ensures data integrity and authenticity through multiple mechanisms:

1. **Checksum Calculation**: Support for multiple algorithms (CRC32, ADLER32, MD5, SHA256, SHA512)
2. **Integrity Envelopes**: Package data with checksums and timestamps for later verification
3. **Digital Signatures**: Create and verify cryptographic signatures for authenticity
4. **Combined Protection**: Use both checksums and signatures for maximum security

## Components

### ChecksumAlgorithm

An enumeration of supported checksum algorithms:

- **CRC32**: Fast, basic error detection (non-cryptographic)
- **ADLER32**: Faster than CRC32, basic error detection (non-cryptographic)
- **MD5**: Cryptographic hash (deprecated for security-critical applications)
- **SHA256**: Strong cryptographic hash (recommended)
- **SHA512**: Stronger cryptographic hash with longer output

```kotlin
val algorithm = ChecksumAlgorithm.SHA256
val defaultAlgorithm = ChecksumAlgorithm.default() // Returns SHA256
```

### ChecksumUtils

Utility class for calculating and verifying checksums:

```kotlin
// Calculate checksum from byte array
val data = "Hello, World!".toByteArray()
val checksum = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.SHA256)

// Calculate checksum from file
val file = File("/path/to/file.txt")
val fileChecksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)

// Calculate checksum from input stream
val inputStream = FileInputStream(file)
val streamChecksum = ChecksumUtils.calculateChecksum(inputStream, ChecksumAlgorithm.SHA256)

// Verify checksum
val isValid = ChecksumUtils.verifyChecksum(data, checksum, ChecksumAlgorithm.SHA256)
```

### IntegrityEnvelope

Data class that packages data with its checksum, algorithm, and timestamp:

```kotlin
// Create integrity envelope (typically done via DataIntegrityManager)
val envelope = IntegrityEnvelope(
    data = data,
    checksum = checksum,
    algorithm = ChecksumAlgorithm.SHA256,
    timestamp = System.currentTimeMillis()
)

// Serialize to JSON
val json = envelope.toJson()

// Deserialize from JSON
val restoredEnvelope = IntegrityEnvelope.fromJson(json)
```

### SignedData

Data class for digitally signed data with signature information:

```kotlin
// Create signed data (typically done via DataIntegrityManager)
val signedData = SignedData(
    data = data,
    signature = signatureBytes,
    signatureAlgorithm = "SHA256withRSA/PSS",
    timestamp = System.currentTimeMillis()
)

// Serialize to JSON
val json = signedData.toJson()

// Deserialize from JSON
val restoredSignedData = SignedData.fromJson(json)
```

### DataIntegrityManager

High-level manager providing comprehensive integrity operations:

#### Creating and Verifying Integrity Envelopes

```kotlin
// Create an integrity envelope
val data = "Important data".toByteArray()
val envelope = DataIntegrityManager.createIntegrityEnvelope(
    data = data,
    algorithm = ChecksumAlgorithm.SHA256  // Optional, defaults to SHA256
)

// Verify integrity
val isValid = DataIntegrityManager.verifyIntegrity(envelope)
if (isValid) {
    println("Data integrity verified!")
} else {
    println("Data has been tampered with!")
}
```

#### Digital Signatures

```kotlin
// Generate key pair (typically done once and stored securely)
val keyPair = DigitalSignature.generateKeyPair("RSA")

// Sign data
val signedData = DataIntegrityManager.signData(data, keyPair.private)

// Verify signature
val isValid = DataIntegrityManager.verifySignature(signedData, keyPair.public)
if (isValid) {
    println("Signature verified - data is authentic!")
} else {
    println("Invalid signature - data may be forged!")
}
```

#### Combined Protection

```kotlin
// Create both integrity envelope and digital signature
val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
    data = data,
    privateKey = keyPair.private,
    algorithm = ChecksumAlgorithm.SHA256  // Optional
)

// Verify both integrity and signature
val isValid = DataIntegrityManager.verifySignedEnvelope(
    envelope = envelope,
    signedData = signedData,
    publicKey = keyPair.public
)
```

## Use Cases

### 1. File Integrity Verification

```kotlin
// Calculate file checksum for distribution
val file = File("/path/to/important-file.zip")
val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
println("File checksum: $checksum")

// Later, verify file integrity
val isUnmodified = ChecksumUtils.verifyChecksum(file, checksum, ChecksumAlgorithm.SHA256)
```

### 2. Data Transmission with Integrity Check

```kotlin
// Sender side
val data = "Sensitive information".toByteArray()
val envelope = DataIntegrityManager.createIntegrityEnvelope(data)
val json = envelope.toJson()
// Send json over network

// Receiver side
val receivedEnvelope = IntegrityEnvelope.fromJson(json)
if (DataIntegrityManager.verifyIntegrity(receivedEnvelope)) {
    // Data received intact
    val data = receivedEnvelope.data
} else {
    // Data corrupted during transmission
}
```

### 3. Authenticated Data Exchange

```kotlin
// Alice signs data with her private key
val aliceKeyPair = DigitalSignature.generateKeyPair("RSA")
val data = "Message from Alice".toByteArray()
val signedData = DataIntegrityManager.signData(data, aliceKeyPair.private)
val json = signedData.toJson()

// Bob verifies with Alice's public key
val receivedData = SignedData.fromJson(json)
if (DataIntegrityManager.verifySignature(receivedData, aliceKeyPair.public)) {
    // Authenticity confirmed - message is from Alice
    println(String(receivedData.data))
} else {
    // Signature invalid - potential forgery
}
```

### 4. Maximum Security with Combined Protection

```kotlin
// Sender creates signed envelope
val senderKeyPair = DigitalSignature.generateKeyPair("RSA")
val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
    data = criticalData,
    privateKey = senderKeyPair.private
)

// Serialize for storage/transmission
val envelopeJson = envelope.toJson()
val signatureJson = signedData.toJson()

// Receiver verifies both integrity and authenticity
val receivedEnvelope = IntegrityEnvelope.fromJson(envelopeJson)
val receivedSignature = SignedData.fromJson(signatureJson)

val isValid = DataIntegrityManager.verifySignedEnvelope(
    receivedEnvelope,
    receivedSignature,
    senderKeyPair.public
)

if (isValid) {
    // Data is both intact and authentic
    processData(receivedEnvelope.data)
}
```

## Algorithm Selection Guide

### For Performance-Critical Applications
- **CRC32** or **ADLER32**: Fast but not secure against malicious tampering
- Best for: Error detection in network protocols, file transfers

### For General Integrity Verification
- **SHA256**: Excellent balance of security and performance
- Best for: File integrity, data validation, most applications

### For Maximum Security
- **SHA512**: Stronger hash with longer output
- Best for: Long-term archival, highly sensitive data

### For Digital Signatures
- **RSA (SHA256withRSA/PSS)**: Industry standard, widely supported
- **ECDSA (SHA256withECDSA)**: More efficient, smaller key sizes
- Best for: Authentication, non-repudiation, secure communications

## Security Considerations

1. **Checksum Algorithms**:
   - CRC32/ADLER32 are NOT cryptographically secure
   - MD5 is deprecated for security-critical applications
   - Use SHA256 or SHA512 for security

2. **Digital Signatures**:
   - Private keys must be kept secure
   - Use secure key generation and storage (Android Keystore)
   - Consider key rotation policies

3. **Timestamp Validation**:
   - Check timestamp freshness to prevent replay attacks
   - Implement time tolerance for clock skew

4. **JSON Serialization**:
   - Data is Base64 encoded in JSON
   - Ensure secure transmission of JSON data
   - Consider encryption for sensitive data

## Error Handling

All methods throw `CryptoOperationException` on failure:

```kotlin
try {
    val envelope = DataIntegrityManager.createIntegrityEnvelope(data)
    val isValid = DataIntegrityManager.verifyIntegrity(envelope)
} catch (e: CryptoOperationException) {
    Log.e("Integrity", "Operation failed: ${e.message}", e)
    // Handle error appropriately
}
```

## Performance Considerations

- **Stream Processing**: Use `InputStream` overloads for large files to avoid loading entire file into memory
- **Buffer Size**: Default 8KB buffer for stream operations
- **Algorithm Choice**: CRC32/ADLER32 are fastest; SHA256 is good balance; SHA512 is slowest
- **Caching**: Consider caching checksums for frequently verified files

## Integration with Other Modules

The Data Integrity module integrates seamlessly with:

- **Digital Signature Module**: Used for signature creation/verification
- **Key Management**: Use with KeyHelper for secure key storage
- **Encryption Modules**: Combine with AES/RSA encryption for complete protection

## Testing

Comprehensive unit tests are available in:
- `ChecksumAlgorithmTest.kt`
- `ChecksumUtilsTest.kt`
- `IntegrityEnvelopeTest.kt`
- `SignedDataTest.kt`
- `DataIntegrityManagerTest.kt`

Run tests with:
```bash
./gradlew :cryptolib:testDebugUnitTest
```
