# Certificate Management Module

The Certificate Management module provides comprehensive support for handling X.509 certificates in the CryptoKit library. It offers utilities for loading, validating, and managing certificates, as well as certificate pinning for enhanced security.

## Features

- **Certificate Loading**: Load X.509 certificates from multiple sources (files, PEM strings, input streams)
- **Certificate Information Extraction**: Extract and display detailed certificate information
- **Certificate Validation**: Validate individual certificates and certificate chains
- **Certificate Pinning**: Pin certificates to specific hosts to prevent man-in-the-middle attacks
- **Expiry Checking**: Check certificate validity periods and expiration status
- **Fingerprint Generation**: Calculate certificate fingerprints using various algorithms (SHA-256, SHA-1, MD5)

## Components

### 1. CertificateInfo
Data class containing extracted certificate information:
- Subject and Issuer distinguished names
- Serial number
- Validity period (notBefore, notAfter)
- Algorithms (public key, signature)
- Validation status
- Days until expiry

### 2. CertificateUtils
Utility object for certificate operations:
- `loadCertificate(inputStream)` - Load from InputStream
- `loadCertificate(pemString)` - Load from PEM string
- `loadCertificateFromFile(file)` - Load from file
- `getCertificateInfo(cert)` - Extract certificate information
- `isExpired(cert)` - Check if expired
- `isNotYetValid(cert)` - Check if not yet valid
- `getDaysUntilExpiry(cert)` - Get days until expiry
- `getFingerprint(cert, algorithm)` - Calculate fingerprint

### 3. CertificateValidator
Certificate validation operations:
- `validateCertificate(cert)` - Validate single certificate
- `validateChain(chain)` - Validate certificate chain
- `verifyCertificateSignature(cert, publicKey)` - Verify signature
- `checkRevocation(cert)` - Check revocation status (placeholder for OCSP/CRL)

### 4. ValidationResult
Data class for validation results:
- `isValid` - Whether validation passed
- `errors` - List of error messages
- `warnings` - List of warning messages

Factory methods:
- `ValidationResult.success(warnings)` - Create success result
- `ValidationResult.failure(errors, warnings)` - Create failure result

### 5. CertificatePinning
Certificate pinning for security:
- `addPin(host, sha256Pin)` - Pin certificate to host
- `removePin(host)` - Remove pin for host
- `verifyPin(host, certificate)` - Verify certificate matches pin
- `getPinForHost(host)` - Get pin for host
- `clearAllPins()` - Clear all pins
- `getAllPins()` - Get all configured pins

## Usage Examples

### Loading and Validating a Certificate

```kotlin
import io.github.romantsisyk.cryptolib.certificates.CertificateUtils
import io.github.romantsisyk.cryptolib.certificates.CertificateValidator
import java.io.File

// Load certificate from file
val certificate = CertificateUtils.loadCertificateFromFile(File("path/to/cert.pem"))

// Get certificate information
val certInfo = CertificateUtils.getCertificateInfo(certificate)
println("Subject: ${certInfo.subject}")
println("Valid until: ${certInfo.notAfter}")
println("Days until expiry: ${certInfo.daysUntilExpiry}")

// Validate the certificate
val result = CertificateValidator.validateCertificate(certificate)
if (result.isValid) {
    println("Certificate is valid!")
} else {
    println("Errors: ${result.errors}")
}
```

### Loading from PEM String

```kotlin
val pemString = """
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKZ...
    -----END CERTIFICATE-----
"""

val certificate = CertificateUtils.loadCertificate(pemString)
```

### Certificate Chain Validation

```kotlin
// Load certificate chain (leaf to root)
val leafCert = CertificateUtils.loadCertificateFromFile(File("leaf.pem"))
val intermediateCert = CertificateUtils.loadCertificateFromFile(File("intermediate.pem"))
val rootCert = CertificateUtils.loadCertificateFromFile(File("root.pem"))

// Validate the chain
val chain = listOf(leafCert, intermediateCert, rootCert)
val result = CertificateValidator.validateChain(chain)

if (result.isValid) {
    println("Certificate chain is valid!")
} else {
    println("Chain validation failed: ${result.errors}")
}
```

### Certificate Pinning

```kotlin
import io.github.romantsisyk.cryptolib.certificates.CertificatePinning

// Get certificate fingerprint
val fingerprint = CertificateUtils.getFingerprint(certificate, "SHA-256")

// Pin the certificate to a host
CertificatePinning.addPin("api.example.com", fingerprint)

// Later, verify a certificate matches the pin
val isValid = CertificatePinning.verifyPin("api.example.com", serverCertificate)
if (!isValid) {
    throw SecurityException("Certificate does not match pin!")
}
```

### Checking Certificate Expiry

```kotlin
val daysUntilExpiry = CertificateUtils.getDaysUntilExpiry(certificate)

when {
    CertificateUtils.isExpired(certificate) -> {
        println("Certificate has expired!")
    }
    daysUntilExpiry <= 30 -> {
        println("Certificate expires in $daysUntilExpiry days")
    }
    else -> {
        println("Certificate is valid")
    }
}
```

### Getting Certificate Fingerprints

```kotlin
// Get different fingerprint types
val sha256 = CertificateUtils.getFingerprint(certificate, "SHA-256")
val sha1 = CertificateUtils.getFingerprint(certificate, "SHA-1")
val md5 = CertificateUtils.getFingerprint(certificate, "MD5")

println("SHA-256: $sha256")
println("SHA-1: $sha1")
println("MD5: $md5")
```

### Complete HTTPS Pinning Example

```kotlin
// 1. Load expected server certificate
val expectedCert = CertificateUtils.loadCertificateFromFile(File("server.pem"))

// 2. Validate it
val validation = CertificateValidator.validateCertificate(expectedCert)
require(validation.isValid) { "Invalid certificate: ${validation.errors}" }

// 3. Pin it
val pin = CertificateUtils.getFingerprint(expectedCert, "SHA-256")
CertificatePinning.addPin("api.example.com", pin)

// 4. During HTTPS connection, verify the server certificate
fun verifyServerCertificate(serverCert: X509Certificate, hostname: String): Boolean {
    return CertificatePinning.verifyPin(hostname, serverCert)
}
```

## Error Handling

All certificate operations can throw `CertificateException`:

```kotlin
import io.github.romantsisyk.cryptolib.exceptions.CertificateException

try {
    val cert = CertificateUtils.loadCertificateFromFile(File("cert.pem"))
    // ... use certificate
} catch (e: CertificateException) {
    println("Certificate error: ${e.message}")
    e.cause?.let { println("Cause: ${it.message}") }
}
```

## Best Practices

1. **Always validate certificates** before trusting them
2. **Use certificate pinning** for critical connections to prevent MITM attacks
3. **Monitor certificate expiry** and renew before expiration
4. **Use SHA-256** for fingerprints (more secure than SHA-1 or MD5)
5. **Validate certificate chains** to ensure the entire trust path is valid
6. **Handle exceptions** appropriately and log certificate errors
7. **Store pins securely** and update them when certificates are rotated

## Security Considerations

- Certificate pinning provides protection against compromised CAs
- Pins should be updated when certificates are rotated
- Always verify the entire certificate chain, not just the leaf certificate
- Monitor certificate expiry and plan for renewal
- Use strong hash algorithms (SHA-256) for fingerprints

## Thread Safety

- `CertificateUtils` and `CertificateValidator` are thread-safe (stateless objects)
- `CertificatePinning` uses `ConcurrentHashMap` for thread-safe pin storage
- All data classes (`CertificateInfo`, `ValidationResult`) are immutable

## Future Enhancements

The following features are planned for future releases:

- OCSP (Online Certificate Status Protocol) support
- CRL (Certificate Revocation List) checking
- Certificate generation utilities
- Integration with Android's Network Security Configuration
- Support for certificate key usage validation
- Extended validation (EV) certificate support
