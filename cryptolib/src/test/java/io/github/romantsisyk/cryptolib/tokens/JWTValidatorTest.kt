package io.github.romantsisyk.cryptolib.tokens

import io.github.romantsisyk.cryptolib.exceptions.TokenException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.util.Date
import javax.crypto.KeyGenerator

class JWTValidatorTest {

    private fun generateHmacKey(): javax.crypto.SecretKey {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA256")
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }

    private fun generateRsaKeyPair(): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        return keyPairGenerator.generateKeyPair()
    }

    @Test
    fun `test parse extracts payload from valid JWT`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setIssuer("test-issuer")
            .addClaim("role", "admin")
            .sign(key, JWTAlgorithm.HS256)

        val payload = JWTValidator.parse(token)

        assertEquals("test-subject", payload.sub)
        assertEquals("test-issuer", payload.iss)
        assertEquals("admin", payload.customClaims["role"])
    }

    @Test
    fun `test parse throws exception for invalid JWT format`() {
        val invalidToken = "invalid.token"

        assertThrows(TokenException::class.java) {
            JWTValidator.parse(invalidToken)
        }
    }

    @Test
    fun `test parse throws exception for JWT with wrong number of parts`() {
        val invalidToken = "header.payload.signature.extra"

        assertThrows(TokenException::class.java) {
            JWTValidator.parse(invalidToken)
        }
    }

    @Test
    fun `test parseHeader extracts header from valid JWT`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        val header = JWTValidator.parseHeader(token)

        assertEquals(JWTAlgorithm.HS256, header.alg)
        assertEquals("JWT", header.typ)
    }

    @Test
    fun `test validate returns true for valid HMAC signed token`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.validate(token, key))
    }

    @Test
    fun `test validate returns false for HMAC token with wrong key`() {
        val key = generateHmacKey()
        val wrongKey = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertFalse(JWTValidator.validate(token, wrongKey))
    }

    @Test
    fun `test validate returns true for valid RSA signed token`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS256)

        assertTrue(JWTValidator.validate(token, keyPair.public))
    }

    @Test
    fun `test validate returns false for RSA token with wrong key`() {
        val keyPair1 = generateRsaKeyPair()
        val keyPair2 = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair1.private, JWTAlgorithm.RS256)

        assertFalse(JWTValidator.validate(token, keyPair2.public))
    }

    @Test
    fun `test validate throws exception for invalid token format`() {
        val key = generateHmacKey()
        val invalidToken = "invalid.token"

        assertThrows(TokenException::class.java) {
            JWTValidator.validate(invalidToken, key)
        }
    }

    @Test
    fun `test validate with HS384 algorithm`() {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA384")
        keyGenerator.init(384)
        val key = keyGenerator.generateKey()

        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS384)

        assertTrue(JWTValidator.validate(token, key))
    }

    @Test
    fun `test validate with HS512 algorithm`() {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA512")
        keyGenerator.init(512)
        val key = keyGenerator.generateKey()

        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS512)

        assertTrue(JWTValidator.validate(token, key))
    }

    @Test
    fun `test validate with RS384 algorithm`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS384)

        assertTrue(JWTValidator.validate(token, keyPair.public))
    }

    @Test
    fun `test validate with RS512 algorithm`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS512)

        assertTrue(JWTValidator.validate(token, keyPair.public))
    }

    @Test
    fun `test isExpired returns true for expired token`() {
        val key = generateHmacKey()
        val pastTime = (System.currentTimeMillis() / 1000) - 3600
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setExpirationSeconds(pastTime)
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.isExpired(token))
    }

    @Test
    fun `test isExpired returns false for valid token`() {
        val key = generateHmacKey()
        val futureTime = (System.currentTimeMillis() / 1000) + 3600
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setExpirationSeconds(futureTime)
            .sign(key, JWTAlgorithm.HS256)

        assertFalse(JWTValidator.isExpired(token))
    }

    @Test
    fun `test isExpired returns false when exp is not set`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertFalse(JWTValidator.isExpired(token))
    }

    @Test
    fun `test getClaim retrieves standard claims`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setIssuer("test-issuer")
            .setSubject("test-subject")
            .setAudience("test-audience")
            .sign(key, JWTAlgorithm.HS256)

        assertEquals("test-issuer", JWTValidator.getClaim(token, "iss"))
        assertEquals("test-subject", JWTValidator.getClaim(token, "sub"))
        assertEquals("test-audience", JWTValidator.getClaim(token, "aud"))
    }

    @Test
    fun `test getClaim retrieves custom claims`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .addClaim("userId", "12345")
            .addClaim("role", "admin")
            .sign(key, JWTAlgorithm.HS256)

        assertEquals("12345", JWTValidator.getClaim(token, "userId"))
        assertEquals("admin", JWTValidator.getClaim(token, "role"))
    }

    @Test
    fun `test getAllClaims retrieves all claims`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setIssuer("issuer")
            .setSubject("subject")
            .addClaim("role", "admin")
            .sign(key, JWTAlgorithm.HS256)

        val claims = JWTValidator.getAllClaims(token)

        assertEquals("issuer", claims["iss"])
        assertEquals("subject", claims["sub"])
        assertEquals("admin", claims["role"])
    }

    @Test
    fun `test validateWithExpiry returns true for valid non-expired token`() {
        val key = generateHmacKey()
        val futureTime = Date(System.currentTimeMillis() + 3600000)
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setExpiration(futureTime)
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.validateWithExpiry(token, key))
    }

    @Test
    fun `test validateWithExpiry throws exception for expired token`() {
        val key = generateHmacKey()
        val pastTime = Date(System.currentTimeMillis() - 3600000)
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setExpiration(pastTime)
            .sign(key, JWTAlgorithm.HS256)

        assertThrows(TokenException::class.java) {
            JWTValidator.validateWithExpiry(token, key)
        }
    }

    @Test
    fun `test validateWithExpiry allows expired token when allowExpired is true`() {
        val key = generateHmacKey()
        val pastTime = Date(System.currentTimeMillis() - 3600000)
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setExpiration(pastTime)
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.validateWithExpiry(token, key, allowExpired = true))
    }

    @Test
    fun `test validateWithExpiry throws exception for not yet valid token`() {
        val key = generateHmacKey()
        val futureTime = Date(System.currentTimeMillis() + 3600000)
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setNotBefore(futureTime)
            .sign(key, JWTAlgorithm.HS256)

        assertThrows(TokenException::class.java) {
            JWTValidator.validateWithExpiry(token, key)
        }
    }

    @Test
    fun `test validateWithExpiry returns false for invalid signature`() {
        val key = generateHmacKey()
        val wrongKey = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertFalse(JWTValidator.validateWithExpiry(token, wrongKey))
    }

    @Test
    fun `test complete JWT lifecycle with HMAC`() {
        val key = generateHmacKey()

        // Create token
        val token = JWTBuilder()
            .setIssuer("test-service")
            .setSubject("user123")
            .setAudience("api")
            .setExpiration(Date(System.currentTimeMillis() + 3600000))
            .setIssuedAt(Date())
            .addClaim("role", "admin")
            .generateJwtId()
            .sign(key, JWTAlgorithm.HS256)

        // Validate token
        assertTrue(JWTValidator.validate(token, key))

        // Parse and verify claims
        val payload = JWTValidator.parse(token)
        assertEquals("test-service", payload.iss)
        assertEquals("user123", payload.sub)
        assertEquals("api", payload.aud)
        assertEquals("admin", payload.customClaims["role"])
        assertNotNull(payload.jti)

        // Check expiration
        assertFalse(JWTValidator.isExpired(token))

        // Get individual claims
        assertEquals("user123", JWTValidator.getClaim(token, "sub"))
        assertEquals("admin", JWTValidator.getClaim(token, "role"))
    }

    @Test
    fun `test complete JWT lifecycle with RSA`() {
        val keyPair = generateRsaKeyPair()

        // Create token
        val token = JWTBuilder()
            .setIssuer("test-service")
            .setSubject("user123")
            .setExpiration(Date(System.currentTimeMillis() + 3600000))
            .addClaim("permissions", listOf("read", "write"))
            .sign(keyPair.private, JWTAlgorithm.RS256)

        // Validate token
        assertTrue(JWTValidator.validate(token, keyPair.public))

        // Parse and verify claims
        val payload = JWTValidator.parse(token)
        assertEquals("test-service", payload.iss)
        assertEquals("user123", payload.sub)

        // Verify wrong key fails
        val wrongKeyPair = generateRsaKeyPair()
        assertFalse(JWTValidator.validate(token, wrongKeyPair.public))
    }
}
