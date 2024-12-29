package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown during authentication failures.
 */
class AuthenticationException(message: String, cause: Throwable? = null) : CryptoLibException(message, cause)