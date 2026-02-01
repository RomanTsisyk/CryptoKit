package io.github.romantsisyk.cryptolib.exceptions

/**
 * Exception thrown when a storage operation fails.
 * This includes failures in encrypted preferences or file storage operations.
 *
 * @param message The detail message describing the failure.
 * @param cause The underlying cause of this exception (optional).
 */
class StorageException(message: String, cause: Throwable? = null) : CryptoLibException(message, cause)
