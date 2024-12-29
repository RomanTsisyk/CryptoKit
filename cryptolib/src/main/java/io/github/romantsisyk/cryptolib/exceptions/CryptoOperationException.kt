package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown when a cryptographic operation fails.
 */
class CryptoOperationException(message: String, cause: Throwable?) : CryptoLibException(message, cause)