package io.github.romantsisyk.cryptolib.exceptions

/**
 * Sealed base exception class for all exceptions in the CryptoLib library.
 * Enables exhaustive `when` matching on exception subtypes.
 */
sealed class CryptoLibException(message: String, cause: Throwable? = null) : Exception(message, cause)