package io.github.romantsisyk.cryptolib.certificates

import java.util.Date

/**
 * Data class containing information extracted from an X.509 certificate.
 *
 * @property subject The subject distinguished name of the certificate holder.
 * @property issuer The issuer distinguished name who signed the certificate.
 * @property serialNumber The unique serial number of the certificate.
 * @property notBefore The date from which the certificate is valid.
 * @property notAfter The date after which the certificate expires.
 * @property publicKeyAlgorithm The algorithm used for the public key.
 * @property signatureAlgorithm The algorithm used to sign the certificate.
 * @property isValid Whether the certificate is currently valid (not expired and not before validity period).
 * @property daysUntilExpiry Number of days until the certificate expires (negative if already expired).
 */
data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val notBefore: Date,
    val notAfter: Date,
    val publicKeyAlgorithm: String,
    val signatureAlgorithm: String,
    val isValid: Boolean,
    val daysUntilExpiry: Long
)
