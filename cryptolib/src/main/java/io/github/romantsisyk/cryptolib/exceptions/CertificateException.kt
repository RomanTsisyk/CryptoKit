package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown when a certificate operation fails.
 * @param message The detail message describing the failure.
 * @param cause The underlying cause of this exception (optional).
 */
class CertificateException(message: String, cause: Throwable? = null) : CryptoLibException(message, cause)
