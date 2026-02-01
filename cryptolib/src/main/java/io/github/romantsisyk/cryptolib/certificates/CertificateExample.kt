package io.github.romantsisyk.cryptolib.certificates

import io.github.romantsisyk.cryptolib.exceptions.CertificateException
import java.io.File
import java.io.FileInputStream
import java.security.cert.X509Certificate

/**
 * Example demonstrating the usage of the Certificate Management module.
 * This class provides practical examples of common certificate operations.
 */
object CertificateExample {

    /**
     * Example: Loading and validating a certificate from a file.
     *
     * @param certificatePath Path to the certificate file (PEM or DER format).
     */
    fun loadAndValidateCertificate(certificatePath: String) {
        try {
            // Load certificate from file
            val file = File(certificatePath)
            val certificate = CertificateUtils.loadCertificateFromFile(file)

            // Get certificate information
            val certInfo = CertificateUtils.getCertificateInfo(certificate)
            println("Certificate Information:")
            println("  Subject: ${certInfo.subject}")
            println("  Issuer: ${certInfo.issuer}")
            println("  Serial Number: ${certInfo.serialNumber}")
            println("  Valid From: ${certInfo.notBefore}")
            println("  Valid Until: ${certInfo.notAfter}")
            println("  Public Key Algorithm: ${certInfo.publicKeyAlgorithm}")
            println("  Signature Algorithm: ${certInfo.signatureAlgorithm}")
            println("  Is Valid: ${certInfo.isValid}")
            println("  Days Until Expiry: ${certInfo.daysUntilExpiry}")

            // Validate the certificate
            val validationResult = CertificateValidator.validateCertificate(certificate)
            if (validationResult.isValid) {
                println("Certificate is valid!")
                if (validationResult.warnings.isNotEmpty()) {
                    println("Warnings:")
                    validationResult.warnings.forEach { println("  - $it") }
                }
            } else {
                println("Certificate validation failed!")
                println("Errors:")
                validationResult.errors.forEach { println("  - $it") }
            }
        } catch (e: CertificateException) {
            println("Error loading certificate: ${e.message}")
        }
    }

    /**
     * Example: Loading a certificate from a PEM string.
     *
     * @param pemString PEM-encoded certificate string.
     */
    fun loadFromPemString(pemString: String) {
        try {
            val certificate = CertificateUtils.loadCertificate(pemString)
            val fingerprint = CertificateUtils.getFingerprint(certificate)
            println("Certificate loaded successfully")
            println("SHA-256 Fingerprint: $fingerprint")
        } catch (e: CertificateException) {
            println("Error loading certificate from PEM: ${e.message}")
        }
    }

    /**
     * Example: Validating a certificate chain.
     *
     * @param certificateFiles List of certificate file paths (leaf to root order).
     */
    fun validateCertificateChain(certificateFiles: List<String>) {
        try {
            // Load all certificates in the chain
            val chain = certificateFiles.map { path ->
                CertificateUtils.loadCertificateFromFile(File(path))
            }

            // Validate the entire chain
            val validationResult = CertificateValidator.validateChain(chain)
            if (validationResult.isValid) {
                println("Certificate chain is valid!")
            } else {
                println("Certificate chain validation failed!")
                println("Errors:")
                validationResult.errors.forEach { println("  - $it") }
            }
        } catch (e: CertificateException) {
            println("Error validating certificate chain: ${e.message}")
        }
    }

    /**
     * Example: Certificate pinning for a domain.
     *
     * @param hostname The hostname to pin (e.g., "api.example.com").
     * @param certificate The certificate to pin.
     */
    fun pinCertificateForHost(hostname: String, certificate: X509Certificate) {
        try {
            // Get the certificate fingerprint
            val pin = CertificateUtils.getFingerprint(certificate, "SHA-256")

            // Add the pin
            CertificatePinning.addPin(hostname, pin)
            println("Certificate pinned for host: $hostname")
            println("Pin: $pin")

            // Later, verify the certificate matches the pin
            val isValid = CertificatePinning.verifyPin(hostname, certificate)
            if (isValid) {
                println("Certificate matches the pin for $hostname")
            } else {
                println("Certificate does NOT match the pin for $hostname")
            }
        } catch (e: CertificateException) {
            println("Error pinning certificate: ${e.message}")
        }
    }

    /**
     * Example: Checking certificate expiry status.
     *
     * @param certificate The certificate to check.
     */
    fun checkCertificateExpiry(certificate: X509Certificate) {
        val daysUntilExpiry = CertificateUtils.getDaysUntilExpiry(certificate)

        when {
            CertificateUtils.isExpired(certificate) -> {
                println("WARNING: Certificate has expired ${-daysUntilExpiry} days ago!")
            }
            CertificateUtils.isNotYetValid(certificate) -> {
                println("WARNING: Certificate is not yet valid (valid in $daysUntilExpiry days)")
            }
            daysUntilExpiry <= 30 -> {
                println("WARNING: Certificate will expire in $daysUntilExpiry days!")
            }
            else -> {
                println("Certificate is valid and will expire in $daysUntilExpiry days")
            }
        }
    }

    /**
     * Example: Getting different types of fingerprints.
     *
     * @param certificate The certificate to fingerprint.
     */
    fun getCertificateFingerprints(certificate: X509Certificate) {
        try {
            val sha256 = CertificateUtils.getFingerprint(certificate, "SHA-256")
            val sha1 = CertificateUtils.getFingerprint(certificate, "SHA-1")
            val md5 = CertificateUtils.getFingerprint(certificate, "MD5")

            println("Certificate Fingerprints:")
            println("  SHA-256: $sha256")
            println("  SHA-1:   $sha1")
            println("  MD5:     $md5")
        } catch (e: CertificateException) {
            println("Error calculating fingerprints: ${e.message}")
        }
    }

    /**
     * Example: Complete workflow for secure HTTPS connection with certificate pinning.
     *
     * @param hostname The hostname to connect to.
     * @param certificatePath Path to the expected server certificate.
     */
    fun secureHttpsConnectionExample(hostname: String, certificatePath: String) {
        try {
            // 1. Load the expected server certificate
            val expectedCert = CertificateUtils.loadCertificateFromFile(File(certificatePath))

            // 2. Validate the certificate
            val validationResult = CertificateValidator.validateCertificate(expectedCert)
            if (!validationResult.isValid) {
                println("Expected certificate is invalid!")
                validationResult.errors.forEach { println("  - $it") }
                return
            }

            // 3. Pin the certificate
            val pin = CertificateUtils.getFingerprint(expectedCert, "SHA-256")
            CertificatePinning.addPin(hostname, pin)
            println("Certificate pinned for $hostname")

            // 4. When receiving a certificate from the server during connection,
            //    verify it matches the pin
            // (In real usage, this would be the certificate from the SSL/TLS handshake)
            val serverCert = expectedCert // In reality, this comes from the server

            val isPinValid = CertificatePinning.verifyPin(hostname, serverCert)
            if (isPinValid) {
                println("Server certificate matches the pin. Connection is secure!")
            } else {
                println("WARNING: Server certificate does NOT match the pin!")
                println("Possible man-in-the-middle attack!")
            }
        } catch (e: CertificateException) {
            println("Error in secure HTTPS connection: ${e.message}")
        }
    }
}
