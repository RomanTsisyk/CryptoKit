package io.github.romantsisyk.cryptolib.tokens

import io.github.romantsisyk.cryptolib.exceptions.TokenException
import java.security.Key
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64
import java.util.Date
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Builder class for creating and signing JSON Web Tokens (JWTs).
 * Provides a fluent API for setting standard claims and custom claims.
 */
class JWTBuilder {
    private var issuer: String? = null
    private var subject: String? = null
    private var audience: String? = null
    private var expiration: Long? = null
    private var issuedAt: Long? = null
    private var notBefore: Long? = null
    private var jwtId: String? = null
    private val customClaims = mutableMapOf<String, Any>()

    /**
     * Sets the issuer (iss) claim.
     * @param iss The issuer value.
     * @return This builder instance for chaining.
     */
    fun setIssuer(iss: String): JWTBuilder {
        this.issuer = iss
        return this
    }

    /**
     * Sets the subject (sub) claim.
     * @param sub The subject value.
     * @return This builder instance for chaining.
     */
    fun setSubject(sub: String): JWTBuilder {
        this.subject = sub
        return this
    }

    /**
     * Sets the audience (aud) claim.
     * @param aud The audience value.
     * @return This builder instance for chaining.
     */
    fun setAudience(aud: String): JWTBuilder {
        this.audience = aud
        return this
    }

    /**
     * Sets the expiration time (exp) claim.
     * @param exp The expiration date.
     * @return This builder instance for chaining.
     */
    fun setExpiration(exp: Date): JWTBuilder {
        this.expiration = exp.time / 1000
        return this
    }

    /**
     * Sets the expiration time (exp) claim in seconds from epoch.
     * @param exp The expiration time in seconds.
     * @return This builder instance for chaining.
     */
    fun setExpirationSeconds(exp: Long): JWTBuilder {
        this.expiration = exp
        return this
    }

    /**
     * Sets the issued at (iat) claim.
     * @param iat The issued at date.
     * @return This builder instance for chaining.
     */
    fun setIssuedAt(iat: Date): JWTBuilder {
        this.issuedAt = iat.time / 1000
        return this
    }

    /**
     * Sets the issued at (iat) claim in seconds from epoch.
     * @param iat The issued at time in seconds.
     * @return This builder instance for chaining.
     */
    fun setIssuedAtSeconds(iat: Long): JWTBuilder {
        this.issuedAt = iat
        return this
    }

    /**
     * Sets the not before (nbf) claim.
     * @param nbf The not before date.
     * @return This builder instance for chaining.
     */
    fun setNotBefore(nbf: Date): JWTBuilder {
        this.notBefore = nbf.time / 1000
        return this
    }

    /**
     * Sets the not before (nbf) claim in seconds from epoch.
     * @param nbf The not before time in seconds.
     * @return This builder instance for chaining.
     */
    fun setNotBeforeSeconds(nbf: Long): JWTBuilder {
        this.notBefore = nbf
        return this
    }

    /**
     * Sets the JWT ID (jti) claim.
     * @param jti The JWT ID value.
     * @return This builder instance for chaining.
     */
    fun setJwtId(jti: String): JWTBuilder {
        this.jwtId = jti
        return this
    }

    /**
     * Generates and sets a random JWT ID (jti) claim.
     * @return This builder instance for chaining.
     */
    fun generateJwtId(): JWTBuilder {
        this.jwtId = UUID.randomUUID().toString()
        return this
    }

    /**
     * Adds a custom claim to the payload.
     * @param key The claim key.
     * @param value The claim value.
     * @return This builder instance for chaining.
     */
    fun addClaim(key: String, value: Any): JWTBuilder {
        // Prevent overwriting standard claims
        val standardClaims = setOf("iss", "sub", "aud", "exp", "iat", "nbf", "jti")
        if (key in standardClaims) {
            throw IllegalArgumentException("Cannot use standard claim name '$key' as custom claim. Use the appropriate setter method instead.")
        }
        customClaims[key] = value
        return this
    }

    /**
     * Builds the JWT payload.
     * @return A JWTPayload instance.
     */
    fun build(): JWTPayload {
        return JWTPayload(
            iss = issuer,
            sub = subject,
            aud = audience,
            exp = expiration,
            iat = issuedAt,
            nbf = notBefore,
            jti = jwtId,
            customClaims = customClaims.toMap()
        )
    }

    /**
     * Signs the JWT using the specified key and algorithm.
     * @param key The key to use for signing (SecretKey for HMAC, PrivateKey for RSA).
     * @param algorithm The JWT algorithm to use.
     * @return A signed JWT string in the format: header.payload.signature
     * @throws TokenException if the signing process fails.
     */
    fun sign(key: Key, algorithm: JWTAlgorithm): String {
        return try {
            // Create header
            val header = JWTHeader(alg = algorithm)
            val headerJson = header.toJson()
            val encodedHeader = base64UrlEncode(headerJson.toByteArray())

            // Create payload
            val payload = build()
            val payloadJson = payload.toJson()
            val encodedPayload = base64UrlEncode(payloadJson.toByteArray())

            // Create signature — validate key type before casting
            val dataToSign = "$encodedHeader.$encodedPayload"
            if (algorithm.isHmac() && key !is SecretKey) {
                throw TokenException(
                    "HMAC algorithm ${algorithm.algorithmName} requires a SecretKey, " +
                        "but got ${key::class.java.simpleName}"
                )
            }
            if (algorithm.isRsa() && key !is PrivateKey) {
                throw TokenException(
                    "RSA algorithm ${algorithm.algorithmName} requires a PrivateKey, " +
                        "but got ${key::class.java.simpleName}"
                )
            }
            val signature = when {
                algorithm.isHmac() -> signHmac(dataToSign, key as SecretKey, algorithm)
                algorithm.isRsa() -> signRsa(dataToSign, key as PrivateKey, algorithm)
                else -> throw TokenException("Unsupported algorithm: ${algorithm.algorithmName}")
            }

            val encodedSignature = base64UrlEncode(signature)

            "$encodedHeader.$encodedPayload.$encodedSignature"
        } catch (e: TokenException) {
            throw e
        } catch (e: Exception) {
            throw TokenException("Failed to sign JWT", e)
        }
    }

    /**
     * Signs data using HMAC algorithm.
     * @param data The data to sign.
     * @param key The secret key.
     * @param algorithm The HMAC algorithm.
     * @return The signature bytes.
     */
    private fun signHmac(data: String, key: SecretKey, algorithm: JWTAlgorithm): ByteArray {
        val mac = Mac.getInstance(algorithm.javaAlgorithm)
        mac.init(key)
        return mac.doFinal(data.toByteArray())
    }

    /**
     * Signs data using RSA algorithm.
     * @param data The data to sign.
     * @param key The private key.
     * @param algorithm The RSA algorithm.
     * @return The signature bytes.
     */
    private fun signRsa(data: String, key: PrivateKey, algorithm: JWTAlgorithm): ByteArray {
        val signature = Signature.getInstance(algorithm.javaAlgorithm)
        signature.initSign(key)
        signature.update(data.toByteArray())
        return signature.sign()
    }

    /**
     * Base64 URL-safe encoding without padding.
     * @param data The data to encode.
     * @return Base64 URL-encoded string.
     */
    private fun base64UrlEncode(data: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data)
    }
}
