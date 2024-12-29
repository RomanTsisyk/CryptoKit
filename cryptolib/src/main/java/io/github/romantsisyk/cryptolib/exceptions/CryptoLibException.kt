package io.github.romantsisyk.cryptolib.exceptions

/**
 * Base exception class for all exceptions in the CryptoLib library.
 */
open class CryptoLibException(message: String, cause: Throwable? = null) : Exception(message, cause)