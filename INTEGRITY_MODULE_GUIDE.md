# Data Integrity Module - Implementation Guide

## Overview

The Data Integrity module has been successfully added to CryptoKit, providing comprehensive functionality for checksums, data validation, and digital signatures.

## Module Structure

```
cryptolib/src/main/java/io/github/romantsisyk/cryptolib/integrity/
├── ChecksumAlgorithm.kt          (60 lines)   - Enum for supported algorithms
├── ChecksumUtils.kt              (179 lines)  - Checksum calculation utilities
├── DataIntegrityManager.kt       (204 lines)  - High-level integrity manager
├── IntegrityEnvelope.kt          (129 lines)  - Data + checksum + timestamp wrapper
├── SignedData.kt                 (127 lines)  - Digitally signed data wrapper
├── IntegrityExamples.kt          (229 lines)  - Usage examples
└── README.md                                  - Comprehensive documentation

cryptolib/src/test/java/io/github/romantsisyk/cryptolib/integrity/
├── ChecksumAlgorithmTest.kt      (58 lines)   - 7 test cases
├── ChecksumUtilsTest.kt          (214 lines)  - 22 test cases
├── DataIntegrityManagerTest.kt   (395 lines)  - 25 test cases
├── IntegrityEnvelopeTest.kt      (268 lines)  - 20 test cases
└── SignedDataTest.kt             (286 lines)  - 20 test cases

Statistics:
- Source code: 928 lines
- Test code: 1,221 lines
- Total: 2,149 lines
- Test cases: 94
```

## Key Features

### 1. Checksum Algorithms
- **CRC32**: Fast, basic error detection
- **ADLER32**: Faster than CRC32
- **MD5**: Cryptographic hash (deprecated for security)
- **SHA256**: Recommended for security
- **SHA512**: Maximum security

### 2. ChecksumUtils
Provides utilities for:
- Calculating checksums from byte arrays
- Calculating checksums from files
- Calculating checksums from input streams
- Verifying checksums

### 3. IntegrityEnvelope
Data class containing:
- Original data
- Checksum value
- Algorithm used
- Timestamp
- JSON serialization support

### 4. SignedData
Data class containing:
- Original data
- Digital signature
- Signature algorithm
- Timestamp
- JSON serialization support

### 5. DataIntegrityManager
High-level manager providing:
- Create integrity envelopes
- Verify integrity
- Sign data (RSA/ECDSA)
- Verify signatures
- Combined signed envelopes

## Code Examples

### Basic Checksum
```kotlin
val data = "Hello, World!".toByteArray()
val checksum = ChecksumUtils.calculateChecksum(data, ChecksumAlgorithm.SHA256)
val isValid = ChecksumUtils.verifyChecksum(data, checksum, ChecksumAlgorithm.SHA256)
```

### Integrity Envelope
```kotlin
val envelope = DataIntegrityManager.createIntegrityEnvelope(data)
val json = envelope.toJson()
val restored = IntegrityEnvelope.fromJson(json)
val isValid = DataIntegrityManager.verifyIntegrity(restored)
```

### Digital Signature
```kotlin
val keyPair = DigitalSignature.generateKeyPair("RSA")
val signedData = DataIntegrityManager.signData(data, keyPair.private)
val isValid = DataIntegrityManager.verifySignature(signedData, keyPair.public)
```

### Combined Protection
```kotlin
val (envelope, signedData) = DataIntegrityManager.createSignedEnvelope(
    data = criticalData,
    privateKey = keyPair.private
)
val isValid = DataIntegrityManager.verifySignedEnvelope(
    envelope, signedData, keyPair.public
)
```

## Design Patterns

The module follows CryptoKit's established patterns:

### 1. Object Singletons
- `ChecksumUtils`
- `DataIntegrityManager`

### 2. Exception Handling
All methods throw `CryptoOperationException` with descriptive messages:
```kotlin
throw CryptoOperationException("Checksum calculation failed: data cannot be empty")
```

### 3. Java Interoperability
All public methods use `@JvmStatic` and `@JvmOverloads` for Java compatibility:
```kotlin
@JvmStatic
@JvmOverloads
fun createIntegrityEnvelope(
    data: ByteArray,
    algorithm: ChecksumAlgorithm = ChecksumAlgorithm.default()
): IntegrityEnvelope
```

### 4. Comprehensive Documentation
- KDoc comments on all public APIs
- Parameter descriptions
- Return value descriptions
- Exception documentation
- Usage examples

### 5. Secure Defaults
- Default algorithm: SHA256
- Proper exception handling
- Input validation

## Integration with CryptoKit

The module integrates seamlessly with existing CryptoKit components:

### With DigitalSignature Module
```kotlin
// Uses existing DigitalSignature.sign() and verify() methods
val signedData = DataIntegrityManager.signData(data, privateKey)
```

### With KeyHelper (Android Keystore)
```kotlin
val keyPair = DigitalSignature.generateKeyPair("RSA")
// Keys can be stored in Android Keystore via KeyHelper
```

### With AES/RSA Encryption
```kotlin
// Combine encryption with integrity
val encrypted = AESEncryption.encrypt(data, key)
val envelope = DataIntegrityManager.createIntegrityEnvelope(encrypted.toByteArray())
```

## Testing

The module includes comprehensive unit tests covering:

### ChecksumAlgorithmTest (7 tests)
- Algorithm name validation
- Default algorithm
- String conversion
- Case insensitivity
- Enum access

### ChecksumUtilsTest (22 tests)
- All algorithm types
- Empty data handling
- Consistency verification
- File checksum calculation
- Stream processing
- Large data handling
- Verification logic

### IntegrityEnvelopeTest (20 tests)
- Envelope creation
- JSON serialization/deserialization
- Round-trip conversion
- Invalid JSON handling
- Missing field detection
- Equals/hashCode implementation

### SignedDataTest (20 tests)
- Signed data creation
- JSON serialization/deserialization
- Round-trip conversion
- Invalid JSON handling
- Multiple signature algorithms
- Equals/hashCode implementation

### DataIntegrityManagerTest (25 tests)
- Envelope creation and verification
- Signature creation and verification
- Tampering detection
- Combined protection
- Different algorithms
- Complete workflows

## Usage Recommendations

### For File Distribution
```kotlin
// Publisher
val file = File("myapp.apk")
val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
println("SHA256: $checksum")

// User verifies
val isValid = ChecksumUtils.verifyChecksum(file, publishedChecksum, ChecksumAlgorithm.SHA256)
```

### For Network Transmission
```kotlin
// Sender
val envelope = DataIntegrityManager.createIntegrityEnvelope(data)
sendOverNetwork(envelope.toJson())

// Receiver
val received = IntegrityEnvelope.fromJson(receivedJson)
if (DataIntegrityManager.verifyIntegrity(received)) {
    processData(received.data)
}
```

### For Authentication
```kotlin
// Sign with private key
val signed = DataIntegrityManager.signData(message, privateKey)
sendToRecipient(signed.toJson())

// Verify with public key
val received = SignedData.fromJson(json)
if (DataIntegrityManager.verifySignature(received, publicKey)) {
    // Authenticated!
}
```

### For Maximum Security
```kotlin
// Combine integrity + authenticity
val (envelope, signed) = DataIntegrityManager.createSignedEnvelope(
    criticalData, privateKey
)

// Store both
database.save(envelope.toJson(), signed.toJson())

// Verify both
if (DataIntegrityManager.verifySignedEnvelope(envelope, signed, publicKey)) {
    // Both integrity and authenticity verified
}
```

## Security Considerations

1. **Algorithm Selection**
   - Use SHA256 or SHA512 for security-critical applications
   - CRC32/ADLER32 only for performance-critical, non-security scenarios

2. **Key Management**
   - Store private keys securely (Android Keystore)
   - Never hardcode keys in source code
   - Implement key rotation policies

3. **Timestamp Validation**
   - Check envelope.timestamp for freshness
   - Implement replay attack prevention
   - Account for clock skew

4. **JSON Handling**
   - Data is Base64 encoded in JSON
   - Validate JSON before parsing
   - Consider encrypting JSON for transmission

## Performance Characteristics

### Algorithm Performance (relative)
- CRC32: Fastest (1x baseline)
- ADLER32: Fastest (0.9x)
- MD5: Fast (2x)
- SHA256: Medium (4x)
- SHA512: Slower (6x)

### Memory Efficiency
- Stream processing uses 8KB buffer
- No full file loading for large files
- Efficient for files of any size

### Best Practices
- Use streams for files > 10MB
- Cache checksums for frequently accessed files
- Choose algorithm based on security needs vs. performance

## Running Tests

```bash
# Run all tests
./gradlew :cryptolib:testDebugUnitTest

# Run specific test class
./gradlew :cryptolib:testDebugUnitTest --tests ChecksumUtilsTest

# Run with coverage
./gradlew :cryptolib:testDebugUnitTest jacocoTestReport
```

## Future Enhancements

Potential additions for future versions:

1. **Additional Algorithms**
   - SHA3 family
   - BLAKE2
   - BLAKE3

2. **Streaming Signatures**
   - Sign large files without loading into memory
   - Chunk-based verification

3. **Batch Operations**
   - Multiple file verification
   - Parallel checksum calculation

4. **Integrity Chains**
   - Link multiple envelopes
   - Merkle tree support

5. **Advanced Features**
   - HMAC support
   - Authenticated encryption modes
   - Time-stamping service integration

## Support and Documentation

For detailed usage examples, see:
- `/integrity/README.md` - Comprehensive module documentation
- `/integrity/IntegrityExamples.kt` - 10 practical examples
- Test files - 94 test cases demonstrating all features

## Conclusion

The Data Integrity module is production-ready and fully integrated with CryptoKit. It provides:

- ✅ 5 checksum algorithms
- ✅ 6 main classes
- ✅ 94 comprehensive test cases
- ✅ Complete documentation
- ✅ Practical examples
- ✅ Java interoperability
- ✅ Secure defaults
- ✅ Exception handling
- ✅ JSON serialization

The module follows all CryptoKit patterns and is ready for immediate use.
