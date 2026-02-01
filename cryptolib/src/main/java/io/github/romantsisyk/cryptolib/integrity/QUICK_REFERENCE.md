# Data Integrity Module - Quick Reference

## Import Statements
```kotlin
import io.github.romantsisyk.cryptolib.integrity.*
import io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature
```

## Checksum Algorithms
```kotlin
ChecksumAlgorithm.CRC32     // Fast, non-cryptographic
ChecksumAlgorithm.ADLER32   // Faster, non-cryptographic
ChecksumAlgorithm.MD5       // Cryptographic (deprecated)
ChecksumAlgorithm.SHA256    // Recommended (default)
ChecksumAlgorithm.SHA512    // Maximum security
```

## ChecksumUtils - One-Liners

### Calculate Checksums
```kotlin
// From byte array
val checksum = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.SHA256)

// From file
val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)

// From stream
val checksum = ChecksumUtils.calculateChecksum(inputStream, ChecksumAlgorithm.SHA256)
```

### Verify Checksums
```kotlin
// Byte array
val isValid = ChecksumUtils.verifyChecksum(data, expectedChecksum, ChecksumAlgorithm.SHA256)

// File
val isValid = ChecksumUtils.verifyChecksum(file, expectedChecksum, ChecksumAlgorithm.SHA256)
```

## DataIntegrityManager - Quick Commands

### Integrity Envelopes
```kotlin
// Create
val envelope = DataIntegrityManager.createIntegrityEnvelope(data)

// Verify
val isValid = DataIntegrityManager.verifyIntegrity(envelope)

// Serialize
val json = envelope.toJson()

// Deserialize
val envelope = IntegrityEnvelope.fromJson(json)
```

### Digital Signatures
```kotlin
// Generate keys (once)
val keyPair = DigitalSignature.generateKeyPair("RSA")  // or "EC"

// Sign
val signedData = DataIntegrityManager.signData(data, keyPair.private)

// Verify
val isValid = DataIntegrityManager.verifySignature(signedData, keyPair.public)

// Serialize
val json = signedData.toJson()

// Deserialize
val signedData = SignedData.fromJson(json)
```

### Combined Protection
```kotlin
// Create signed envelope
val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
    data = data,
    privateKey = keyPair.private,
    algorithm = ChecksumAlgorithm.SHA256  // optional
)

// Verify both
val isValid = DataIntegrityManager.verifySignedEnvelope(
    envelope = envelope,
    signedData = signedData,
    publicKey = keyPair.public
)
```

## Common Patterns

### File Distribution Pattern
```kotlin
// Publisher
val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
println("SHA256: $checksum")

// User
val isValid = ChecksumUtils.verifyChecksum(file, publishedChecksum, ChecksumAlgorithm.SHA256)
```

### Network Transmission Pattern
```kotlin
// Sender
val envelope = DataIntegrityManager.createIntegrityEnvelope(data)
transmit(envelope.toJson())

// Receiver
val received = IntegrityEnvelope.fromJson(json)
if (DataIntegrityManager.verifyIntegrity(received)) {
    use(received.data)
}
```

### Authentication Pattern
```kotlin
// Signer
val signed = DataIntegrityManager.signData(message, privateKey)
send(signed.toJson())

// Verifier
val received = SignedData.fromJson(json)
if (DataIntegrityManager.verifySignature(received, publicKey)) {
    trust(received.data)
}
```

### Maximum Security Pattern
```kotlin
// Create
val (env, sig) = DataIntegrityManager.createSignedEnvelope(data, privateKey)

// Verify
if (DataIntegrityManager.verifySignedEnvelope(env, sig, publicKey)) {
    // Both integrity and authenticity verified
}
```

## Data Classes

### IntegrityEnvelope
```kotlin
data class IntegrityEnvelope(
    val data: ByteArray,
    val checksum: String,
    val algorithm: ChecksumAlgorithm,
    val timestamp: Long
)
```

### SignedData
```kotlin
data class SignedData(
    val data: ByteArray,
    val signature: ByteArray,
    val signatureAlgorithm: String,
    val timestamp: Long
)
```

## Exception Handling
```kotlin
try {
    val envelope = DataIntegrityManager.createIntegrityEnvelope(data)
    val isValid = DataIntegrityManager.verifyIntegrity(envelope)
} catch (e: CryptoOperationException) {
    // Handle error: e.message contains details
}
```

## Checksum Output Sizes
```kotlin
CRC32:    8 hex chars    (32 bits)
ADLER32:  8 hex chars    (32 bits)
MD5:     32 hex chars   (128 bits)
SHA256:  64 hex chars   (256 bits)
SHA512: 128 hex chars   (512 bits)
```

## Algorithm Selection Guide

| Use Case | Algorithm | Why |
|----------|-----------|-----|
| File transfer error detection | CRC32/ADLER32 | Fast, good for accidental corruption |
| General integrity | SHA256 | Best balance of security and speed |
| Long-term archival | SHA512 | Maximum security |
| Authentication | RSA/ECDSA signatures | Non-repudiation |
| Performance critical | CRC32 | Fastest |

## Tips

1. **Default is SHA256** - Omit algorithm parameter to use SHA256
2. **Streams for large files** - Use InputStream overloads for files > 10MB
3. **Case insensitive** - Checksum verification ignores case
4. **Timestamp checking** - Validate `envelope.timestamp` for freshness
5. **Key storage** - Store private keys in Android Keystore, not in code

## Testing
```bash
./gradlew :cryptolib:testDebugUnitTest
```

## For More Details
- See `README.md` for comprehensive documentation
- See `IntegrityExamples.kt` for 10 practical examples
- See test files for 94 test cases
