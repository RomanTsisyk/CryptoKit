package io.github.romantsisyk.cryptolib.tokens

import io.github.romantsisyk.cryptolib.exceptions.TokenException
import java.security.Key
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Validator class for verifying and parsing JSON Web Tokens (JWTs).
 * Provides methods for parsing, validating, and extracting claims from JWTs.
 */
object JWTValidator {

    /**
     * Parses a JWT string and extracts the payload without verification.
     * @param token The JWT string to parse.
     * @return The parsed JWTPayload.
     * @throws TokenException if the token format is invalid.
     */
    @JvmStatic
    fun parse(token: String): JWTPayload {
        val parts = token.split(".")
        if (parts.size != 3) {
            throw TokenException("Invalid JWT format: expected 3 parts, found ${parts.size}")
        }

        return try {
            val payloadJson = String(base64UrlDecode(parts[1]))
            JWTPayload.fromJson(payloadJson)
        } catch (e: Exception) {
            throw TokenException("Failed to parse JWT payload", e)
        }
    }

    /**
     * Parses a JWT string and extracts the header without verification.
     * @param token The JWT string to parse.
     * @return The parsed JWTHeader.
     * @throws TokenException if the token format is invalid.
     */
    @JvmStatic
    fun parseHeader(token: String): JWTHeader {
        val parts = token.split(".")
        if (parts.size != 3) {
            throw TokenException("Invalid JWT format: expected 3 parts, found ${parts.size}")
        }

        return try {
            val headerJson = String(base64UrlDecode(parts[0]))
            JWTHeader.fromJson(headerJson)
        } catch (e: Exception) {
            throw TokenException("Failed to parse JWT header", e)
        }
    }

    /**
     * Validates a JWT signature using the provided key.
     *
     * @param token The JWT string to validate.
     * @param key The key to use for validation (SecretKey for HMAC, PublicKey for RSA).
     * @param expectedAlgorithm The algorithm the token MUST use. If the token header
     *        specifies a different algorithm, validation fails with [TokenException].
     *        This parameter is required to prevent algorithm confusion attacks.
     * @return true if the signature is valid, false otherwise.
     * @throws TokenException if validation fails due to an error or algorithm mismatch.
     */
    @JvmStatic
    fun validate(token: String, key: Key, expectedAlgorithm: JWTAlgorithm): Boolean {
        return try {
            val parts = token.split(".")
            if (parts.size != 3) {
                throw TokenException("Invalid JWT format: expected 3 parts, found ${parts.size}")
            }

            val header = parseHeader(token)
            val algorithm = header.alg

            // Enforce expected algorithm to prevent algorithm confusion attacks
            if (algorithm != expectedAlgorithm) {
                throw TokenException(
                    "Algorithm mismatch: token specifies ${algorithm.algorithmName} " +
                        "but expected ${expectedAlgorithm.algorithmName}"
                )
            }

            // Validate key type matches algorithm to prevent ClassCastException
            if (algorithm.isHmac() && key !is SecretKey) {
                throw TokenException(
                    "HMAC algorithm ${algorithm.algorithmName} requires a SecretKey, " +
                        "but got ${key::class.java.simpleName}"
                )
            }
            if (algorithm.isRsa() && key !is PublicKey) {
                throw TokenException(
                    "RSA algorithm ${algorithm.algorithmName} requires a PublicKey, " +
                        "but got ${key::class.java.simpleName}"
                )
            }

            val dataToVerify = "${parts[0]}.${parts[1]}"
            val signature = base64UrlDecode(parts[2])

            when {
                algorithm.isHmac() -> verifyHmac(dataToVerify, signature, key as SecretKey, algorithm)
                algorithm.isRsa() -> verifyRsa(dataToVerify, signature, key as PublicKey, algorithm)
                else -> throw TokenException("Unsupported algorithm: ${algorithm.algorithmName}")
            }
        } catch (e: TokenException) {
            throw e
        } catch (e: Exception) {
            throw TokenException("Failed to validate JWT", e)
        }
    }

    /**
     * Validates a JWT and checks if it's expired.
     * @param token The JWT string to validate.
     * @param key The key to use for validation.
     * @param allowExpired If true, doesn't throw exception for expired tokens.
     * @param expectedAlgorithm The algorithm the token MUST use. Required to prevent
     *        algorithm confusion attacks.
     * @return true if the token is valid and not expired, false otherwise.
     * @throws TokenException if validation fails.
     */
    @JvmStatic
    @JvmOverloads
    fun validateWithExpiry(
        token: String,
        key: Key,
        allowExpired: Boolean = false,
        expectedAlgorithm: JWTAlgorithm
    ): Boolean {
        val isValid = validate(token, key, expectedAlgorithm)
        if (!isValid) {
            return false
        }

        val payload = parse(token)
        if (payload.isExpired() && !allowExpired) {
            throw TokenException("JWT has expired")
        }

        if (payload.isNotYetValid()) {
            throw TokenException("JWT is not yet valid (nbf claim)")
        }

        return true
    }

    /**
     * Checks if a JWT is expired based on the exp claim.
     * @param token The JWT string to check.
     * @return true if the token is expired, false otherwise.
     * @throws TokenException if the token cannot be parsed.
     */
    @JvmStatic
    fun isExpired(token: String): Boolean {
        val payload = parse(token)
        return payload.isExpired()
    }

    /**
     * Retrieves a specific claim from the JWT payload.
     * @param token The JWT string.
     * @param claimName The name of the claim to retrieve.
     * @return The claim value, or null if not found.
     * @throws TokenException if the token cannot be parsed.
     */
    @JvmStatic
    fun getClaim(token: String, claimName: String): Any? {
        val payload = parse(token)
        return when (claimName) {
            "iss" -> payload.iss
            "sub" -> payload.sub
            "aud" -> payload.aud
            "exp" -> payload.exp
            "iat" -> payload.iat
            "nbf" -> payload.nbf
            "jti" -> payload.jti
            else -> payload.customClaims[claimName]
        }
    }

    /**
     * Retrieves all claims from the JWT payload as a map.
     * @param token The JWT string.
     * @return A map containing all claims (standard and custom).
     * @throws TokenException if the token cannot be parsed.
     */
    @JvmStatic
    fun getAllClaims(token: String): Map<String, Any?> {
        val payload = parse(token)
        return buildMap {
            payload.iss?.let { put("iss", it) }
            payload.sub?.let { put("sub", it) }
            payload.aud?.let { put("aud", it) }
            payload.exp?.let { put("exp", it) }
            payload.iat?.let { put("iat", it) }
            payload.nbf?.let { put("nbf", it) }
            payload.jti?.let { put("jti", it) }
            putAll(payload.customClaims)
        }
    }

    /**
     * Verifies HMAC signature.
     * @param data The data that was signed.
     * @param signature The signature to verify.
     * @param key The secret key.
     * @param algorithm The HMAC algorithm.
     * @return true if the signature is valid, false otherwise.
     */
    private fun verifyHmac(data: String, signature: ByteArray, key: SecretKey, algorithm: JWTAlgorithm): Boolean {
        val mac = Mac.getInstance(algorithm.javaAlgorithm)
        mac.init(key)
        val expectedSignature = mac.doFinal(data.toByteArray())
        return MessageDigest.isEqual(signature, expectedSignature)
    }

    /**
     * Verifies RSA signature.
     * @param data The data that was signed.
     * @param signature The signature to verify.
     * @param key The public key.
     * @param algorithm The RSA algorithm.
     * @return true if the signature is valid, false otherwise.
     */
    private fun verifyRsa(data: String, signature: ByteArray, key: PublicKey, algorithm: JWTAlgorithm): Boolean {
        val sig = Signature.getInstance(algorithm.javaAlgorithm)
        sig.initVerify(key)
        sig.update(data.toByteArray())
        return sig.verify(signature)
    }

    /**
     * Base64 URL-safe decoding.
     * @param data The data to decode.
     * @return Decoded byte array.
     */
    private fun base64UrlDecode(data: String): ByteArray {
        return Base64.getUrlDecoder().decode(data)
    }
}
