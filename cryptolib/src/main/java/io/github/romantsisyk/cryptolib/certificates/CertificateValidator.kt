package io.github.romantsisyk.cryptolib.certificates

import io.github.romantsisyk.cryptolib.exceptions.CertificateException
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Object responsible for validating X.509 certificates and certificate chains.
 * Provides methods for certificate validation, signature verification, and chain validation.
 */
object CertificateValidator {

    /**
     * Validates a single X.509 certificate.
     *
     * @param cert The X509Certificate to validate.
     * @return A ValidationResult containing the validation outcome.
     */
    @JvmStatic
    fun validateCertificate(cert: X509Certificate): ValidationResult {
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        try {
            // Check validity period
            cert.checkValidity()
        } catch (e: Exception) {
            when {
                CertificateUtils.isExpired(cert) -> {
                    errors.add("Certificate has expired on ${cert.notAfter}")
                }
                CertificateUtils.isNotYetValid(cert) -> {
                    errors.add("Certificate is not yet valid until ${cert.notBefore}")
                }
                else -> {
                    errors.add("Certificate validity check failed: ${e.message}")
                }
            }
        }

        // Check for expiry warning (certificate expiring within 30 days)
        val daysUntilExpiry = CertificateUtils.getDaysUntilExpiry(cert)
        if (daysUntilExpiry in 0..30) {
            warnings.add("Certificate will expire in $daysUntilExpiry days")
        }

        // Verify certificate version (should be v3 for most modern certificates)
        if (cert.version < 3) {
            warnings.add("Certificate version is ${cert.version}, consider using X.509 v3")
        }

        // Check if certificate has basic constraints extension for CA certificates
        val basicConstraints = cert.basicConstraints
        if (basicConstraints >= 0) {
            // This is a CA certificate
            warnings.add("Certificate is a CA certificate (basicConstraints: $basicConstraints)")
        }

        // Check key usage
        try {
            val keyUsage = cert.keyUsage
            if (keyUsage != null && keyUsage.all { !it }) {
                warnings.add("Certificate has no key usage bits set")
            }
        } catch (e: Exception) {
            warnings.add("Failed to check key usage: ${e.message}")
        }

        return if (errors.isEmpty()) {
            ValidationResult.success(warnings)
        } else {
            ValidationResult.failure(errors, warnings)
        }
    }

    /**
     * Validates a certificate chain.
     *
     * @param chain List of X509Certificates forming the chain (from end-entity to root).
     * @return A ValidationResult containing the validation outcome.
     */
    @JvmStatic
    fun validateChain(chain: List<X509Certificate>): ValidationResult {
        if (chain.isEmpty()) {
            return ValidationResult.failure(listOf("Certificate chain is empty"))
        }

        if (chain.size == 1) {
            return validateCertificate(chain[0])
        }

        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        // Validate each certificate in the chain
        chain.forEachIndexed { index, cert ->
            val result = validateCertificate(cert)
            if (!result.isValid) {
                errors.add("Certificate at position $index is invalid: ${result.errors.joinToString(", ")}")
            }
            warnings.addAll(result.warnings.map { "Certificate at position $index: $it" })
        }

        // Verify chain signatures (each certificate should be signed by the next one)
        for (i in 0 until chain.size - 1) {
            val current = chain[i]
            val issuer = chain[i + 1]

            // Check if issuer matches
            if (current.issuerX500Principal != issuer.subjectX500Principal) {
                errors.add("Certificate at position $i issuer does not match subject of certificate at position ${i + 1}")
            }

            // Verify signature
            try {
                if (!verifyCertificateSignature(current, issuer.publicKey)) {
                    errors.add("Signature verification failed for certificate at position $i")
                }
            } catch (e: Exception) {
                errors.add("Failed to verify signature for certificate at position $i: ${e.message}")
            }
        }

        // Check if the last certificate is self-signed (root CA)
        val rootCert = chain.last()
        if (rootCert.issuerX500Principal == rootCert.subjectX500Principal) {
            try {
                if (!verifyCertificateSignature(rootCert, rootCert.publicKey)) {
                    errors.add("Root certificate signature verification failed")
                }
            } catch (e: Exception) {
                errors.add("Failed to verify root certificate signature: ${e.message}")
            }
        } else {
            warnings.add("Root certificate is not self-signed, chain may be incomplete")
        }

        return if (errors.isEmpty()) {
            ValidationResult.success(warnings)
        } else {
            ValidationResult.failure(errors, warnings)
        }
    }

    /**
     * Verifies the digital signature of a certificate using the issuer's public key.
     *
     * @param cert The X509Certificate whose signature should be verified.
     * @param issuerPublicKey The public key of the issuer.
     * @return true if the signature is valid, false otherwise.
     * @throws CertificateException if verification fails due to an error.
     */
    @JvmStatic
    fun verifyCertificateSignature(cert: X509Certificate, issuerPublicKey: PublicKey): Boolean {
        return try {
            cert.verify(issuerPublicKey)
            true
        } catch (e: java.security.SignatureException) {
            // Signature verification failed - signature is invalid
            false
        } catch (e: Exception) {
            throw CertificateException("Failed to verify certificate signature", e)
        }
    }

    /**
     * Checks if a certificate has been revoked.
     * This is a placeholder for OCSP (Online Certificate Status Protocol) or CRL (Certificate Revocation List) checking.
     *
     * @param cert The X509Certificate to check for revocation.
     * @return true if the certificate is revoked, false otherwise.
     * Note: Currently returns false as this is a placeholder implementation.
     */
    @JvmStatic
    fun checkRevocation(cert: X509Certificate): Boolean {
        // TODO: Implement OCSP or CRL checking
        // This would require:
        // 1. Extracting the OCSP responder URL from the certificate's AIA extension
        // 2. Making an OCSP request to check the certificate status
        // 3. Or downloading and checking the CRL if OCSP is not available

        // For now, return false (not revoked) as a placeholder
        return false
    }
}
