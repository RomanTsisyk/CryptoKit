package io.github.romantsisyk.cryptolib.certificates

import io.github.romantsisyk.cryptolib.exceptions.CertificateException
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * Utility object for working with X.509 certificates.
 * Provides methods for loading, parsing, and extracting information from certificates.
 */
object CertificateUtils {

    private const val CERTIFICATE_TYPE = "X.509"
    private const val PEM_HEADER = "-----BEGIN CERTIFICATE-----"
    private const val PEM_FOOTER = "-----END CERTIFICATE-----"

    /**
     * Loads an X.509 certificate from an InputStream.
     *
     * @param inputStream The input stream containing the certificate data.
     * @return The loaded X509Certificate.
     * @throws CertificateException if the certificate cannot be loaded.
     */
    @JvmStatic
    fun loadCertificate(inputStream: InputStream): X509Certificate {
        return try {
            val certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE)
            val certificate = certificateFactory.generateCertificate(inputStream)

            if (certificate !is X509Certificate) {
                throw CertificateException("Certificate is not an X.509 certificate")
            }

            certificate
        } catch (e: CertificateException) {
            throw e
        } catch (e: Exception) {
            throw CertificateException("Failed to load certificate from input stream", e)
        }
    }

    /**
     * Loads an X.509 certificate from a PEM-encoded string.
     *
     * @param pemString The PEM-encoded certificate string.
     * @return The loaded X509Certificate.
     * @throws CertificateException if the certificate cannot be loaded.
     */
    @JvmStatic
    fun loadCertificate(pemString: String): X509Certificate {
        if (pemString.isBlank()) {
            throw CertificateException("PEM string cannot be empty")
        }

        return try {
            // Remove PEM headers and footers if present
            val cleanedPem = pemString
                .replace(PEM_HEADER, "")
                .replace(PEM_FOOTER, "")
                .replace("\\s".toRegex(), "")

            if (cleanedPem.isEmpty()) {
                throw CertificateException("PEM string contains no certificate data")
            }

            // Decode Base64 and load certificate
            val certificateBytes = Base64.getDecoder().decode(cleanedPem)
            val certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE)
            val certificate = certificateFactory.generateCertificate(certificateBytes.inputStream())

            if (certificate !is X509Certificate) {
                throw CertificateException("Certificate is not an X.509 certificate")
            }

            certificate
        } catch (e: CertificateException) {
            throw e
        } catch (e: IllegalArgumentException) {
            throw CertificateException("Invalid Base64 encoding in PEM string", e)
        } catch (e: Exception) {
            throw CertificateException("Failed to load certificate from PEM string", e)
        }
    }

    /**
     * Loads an X.509 certificate from a file.
     *
     * @param file The file containing the certificate (PEM or DER format).
     * @return The loaded X509Certificate.
     * @throws CertificateException if the certificate cannot be loaded.
     */
    @JvmStatic
    fun loadCertificateFromFile(file: File): X509Certificate {
        if (!file.exists()) {
            throw CertificateException("Certificate file does not exist: ${file.absolutePath}")
        }

        if (!file.canRead()) {
            throw CertificateException("Cannot read certificate file: ${file.absolutePath}")
        }

        return try {
            file.inputStream().use { inputStream ->
                loadCertificate(inputStream)
            }
        } catch (e: CertificateException) {
            throw e
        } catch (e: Exception) {
            throw CertificateException("Failed to load certificate from file: ${file.absolutePath}", e)
        }
    }

    /**
     * Extracts information from an X.509 certificate.
     *
     * @param cert The X509Certificate to extract information from.
     * @return A CertificateInfo object containing the extracted information.
     */
    @JvmStatic
    fun getCertificateInfo(cert: X509Certificate): CertificateInfo {
        val now = Date()
        val daysUntilExpiry = getDaysUntilExpiry(cert)
        val isValid = !isExpired(cert) && !isNotYetValid(cert)

        return CertificateInfo(
            subject = cert.subjectX500Principal.name,
            issuer = cert.issuerX500Principal.name,
            serialNumber = cert.serialNumber.toString(16).uppercase(),
            notBefore = cert.notBefore,
            notAfter = cert.notAfter,
            publicKeyAlgorithm = cert.publicKey.algorithm,
            signatureAlgorithm = cert.sigAlgName,
            isValid = isValid,
            daysUntilExpiry = daysUntilExpiry
        )
    }

    /**
     * Checks if a certificate has expired.
     *
     * @param cert The X509Certificate to check.
     * @return true if the certificate has expired, false otherwise.
     */
    @JvmStatic
    fun isExpired(cert: X509Certificate): Boolean {
        return try {
            cert.checkValidity()
            false
        } catch (e: Exception) {
            Date().after(cert.notAfter)
        }
    }

    /**
     * Checks if a certificate is not yet valid.
     *
     * @param cert The X509Certificate to check.
     * @return true if the certificate is not yet valid, false otherwise.
     */
    @JvmStatic
    fun isNotYetValid(cert: X509Certificate): Boolean {
        return try {
            cert.checkValidity()
            false
        } catch (e: Exception) {
            Date().before(cert.notBefore)
        }
    }

    /**
     * Calculates the number of days until the certificate expires.
     *
     * @param cert The X509Certificate to check.
     * @return Number of days until expiry (negative if already expired).
     */
    @JvmStatic
    fun getDaysUntilExpiry(cert: X509Certificate): Long {
        val now = Date()
        val diffInMillis = cert.notAfter.time - now.time
        return TimeUnit.MILLISECONDS.toDays(diffInMillis)
    }

    /**
     * Calculates the fingerprint (hash) of a certificate.
     *
     * @param cert The X509Certificate to fingerprint.
     * @param algorithm The hash algorithm to use (default: SHA-256).
     * @return The fingerprint as a hex string (colon-separated bytes).
     * @throws CertificateException if the fingerprint cannot be calculated.
     */
    @JvmStatic
    fun getFingerprint(cert: X509Certificate, algorithm: String = "SHA-256"): String {
        return try {
            val digest = MessageDigest.getInstance(algorithm)
            val hash = digest.digest(cert.encoded)
            hash.joinToString(":") { byte -> "%02X".format(byte) }
        } catch (e: Exception) {
            throw CertificateException("Failed to calculate certificate fingerprint with algorithm $algorithm", e)
        }
    }
}
