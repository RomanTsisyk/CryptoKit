package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown when a key is not found in the Keystore.
 * @param alias The alias of the key that could not be found.
 */
class KeyNotFoundException(alias: String) :
    CryptoLibException("Key with alias '$alias' not found in the Keystore.")