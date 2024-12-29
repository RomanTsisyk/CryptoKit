package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown when key generation fails.
 * @param alias The alias for the key that failed to generate.
 * @param cause The cause of the failure.
 */
class KeyGenerationException(alias: String, cause: Throwable?) :
    CryptoLibException("Failed to generate key with alias '$alias'.", cause)