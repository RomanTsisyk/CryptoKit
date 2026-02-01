package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown when a key is not found in the Keystore.
 * @param alias The alias of the key that could not be found.
 * @param cause The underlying cause of this exception (optional).
 */
class KeyNotFoundException(alias: String, cause: Throwable? = null) :
    CryptoLibException("Key with alias '$alias' not found in the Keystore.", cause)