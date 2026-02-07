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

        assertTrue(JWTValidator.validate(token, key, JWTAlgorithm.HS256))
    }

    @Test
    fun `test validate returns false for HMAC token with wrong key`() {
        val key = generateHmacKey()
        val wrongKey = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertFalse(JWTValidator.validate(token, wrongKey, JWTAlgorithm.HS256))
    }

    @Test
    fun `test validate returns true for valid RSA signed token`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS256)

        assertTrue(JWTValidator.validate(token, keyPair.public, JWTAlgorithm.RS256))
    }

    @Test
    fun `test validate returns false for RSA token with wrong key`() {
        val keyPair1 = generateRsaKeyPair()
        val keyPair2 = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair1.private, JWTAlgorithm.RS256)

        assertFalse(JWTValidator.validate(token, keyPair2.public, JWTAlgorithm.RS256))
    }

    @Test
    fun `test validate throws exception for invalid token format`() {
        val key = generateHmacKey()
        val invalidToken = "invalid.token"

        assertThrows(TokenException::class.java) {
            JWTValidator.validate(invalidToken, key, JWTAlgorithm.HS256)
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

        assertTrue(JWTValidator.validate(token, key, JWTAlgorithm.HS384))
    }

    @Test
    fun `test validate with HS512 algorithm`() {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA512")
        keyGenerator.init(512)
        val key = keyGenerator.generateKey()

        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS512)

        assertTrue(JWTValidator.validate(token, key, JWTAlgorithm.HS512))
    }

    @Test
    fun `test validate with RS384 algorithm`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS384)

        assertTrue(JWTValidator.validate(token, keyPair.public, JWTAlgorithm.RS384))
    }

    @Test
    fun `test validate with RS512 algorithm`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS512)

        assertTrue(JWTValidator.validate(token, keyPair.public, JWTAlgorithm.RS512))
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

        assertTrue(JWTValidator.validateWithExpiry(token, key, expectedAlgorithm = JWTAlgorithm.HS256))
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
            JWTValidator.validateWithExpiry(token, key, expectedAlgorithm = JWTAlgorithm.HS256)
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

        assertTrue(JWTValidator.validateWithExpiry(token, key, allowExpired = true, expectedAlgorithm = JWTAlgorithm.HS256))
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
            JWTValidator.validateWithExpiry(token, key, expectedAlgorithm = JWTAlgorithm.HS256)
        }
    }

    @Test
    fun `test validateWithExpiry returns false for invalid signature`() {
        val key = generateHmacKey()
        val wrongKey = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertFalse(JWTValidator.validateWithExpiry(token, wrongKey, expectedAlgorithm = JWTAlgorithm.HS256))
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
        assertTrue(JWTValidator.validate(token, key, JWTAlgorithm.HS256))

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

    // ==================== Algorithm confusion attack tests ====================

    @Test
    fun `test validate rejects token when header alg does not match expectedAlgorithm`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertThrows(TokenException::class.java) {
            JWTValidator.validate(token, key, expectedAlgorithm = JWTAlgorithm.HS512)
        }
    }

    @Test
    fun `test validate succeeds when header alg matches expectedAlgorithm`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.validate(token, key, expectedAlgorithm = JWTAlgorithm.HS256))
    }

    @Test
    fun `test validate rejects HMAC token with wrong key type`() {
        val hmacKey = generateHmacKey()
        val rsaKeyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(hmacKey, JWTAlgorithm.HS256)

        // Attempt to verify HMAC token with an RSA PublicKey should fail with clear error
        assertThrows(TokenException::class.java) {
            JWTValidator.validate(token, rsaKeyPair.public, expectedAlgorithm = JWTAlgorithm.HS256)
        }
    }

    @Test
    fun `test validate rejects RSA token with wrong key type`() {
        val rsaKeyPair = generateRsaKeyPair()
        val hmacKey = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(rsaKeyPair.private, JWTAlgorithm.RS256)

        // Attempt to verify RSA token with an HMAC SecretKey should fail with clear error
        assertThrows(TokenException::class.java) {
            JWTValidator.validate(token, hmacKey, expectedAlgorithm = JWTAlgorithm.RS256)
        }
    }

    @Test
    fun `test validate rejects token with unsupported algorithm in header`() {
        // Craft a token with alg=none by manual Base64 encoding
        val headerJson = """{"alg":"none","typ":"JWT"}"""
        val payloadJson = """{"sub":"test"}"""
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString(headerJson.toByteArray())
        val payload = encoder.encodeToString(payloadJson.toByteArray())
        val token = "$header.$payload."

        val key = generateHmacKey()
        assertThrows(TokenException::class.java) {
            JWTValidator.validate(token, key, JWTAlgorithm.HS256)
        }
    }

    @Test
    fun `test validate detects tampered payload`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("original-subject")
            .sign(key, JWTAlgorithm.HS256)

        // Tamper with the payload: replace the middle part
        val parts = token.split(".")
        val tamperedPayloadJson = """{"sub":"tampered-subject"}"""
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val tamperedPayload = encoder.encodeToString(tamperedPayloadJson.toByteArray())
        val tamperedToken = "${parts[0]}.$tamperedPayload.${parts[2]}"

        assertFalse(JWTValidator.validate(tamperedToken, key, expectedAlgorithm = JWTAlgorithm.HS256))
    }

    @Test
    fun `test validateWithExpiry with expectedAlgorithm`() {
        val key = generateHmacKey()
        val futureTime = Date(System.currentTimeMillis() + 3600000)
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setExpiration(futureTime)
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.validateWithExpiry(token, key, expectedAlgorithm = JWTAlgorithm.HS256))

        assertThrows(TokenException::class.java) {
            JWTValidator.validateWithExpiry(token, key, expectedAlgorithm = JWTAlgorithm.RS256)
        }
    }

    @Test
    fun `test validate rejects HMAC token verified with RSA key`() {
        val hmacKey = generateHmacKey()
        val rsaKeyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(hmacKey, JWTAlgorithm.HS256)

        // Token header says HS256 but we pass an RSA PublicKey — should reject due to key type mismatch
        assertThrows(TokenException::class.java) {
            JWTValidator.validate(token, rsaKeyPair.public, JWTAlgorithm.HS256)
        }
    }

    @Test
    fun `test validate rejects RSA token verified with HMAC key`() {
        val rsaKeyPair = generateRsaKeyPair()
        val hmacKey = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(rsaKeyPair.private, JWTAlgorithm.RS256)

        // Token header says RS256 but we pass an HMAC SecretKey — should reject due to key type mismatch
        assertThrows(TokenException::class.java) {
            JWTValidator.validate(token, hmacKey, JWTAlgorithm.RS256)
        }
    }

    @Test
    fun `test JWTBuilder sign rejects HMAC algorithm with RSA key`() {
        val rsaKeyPair = generateRsaKeyPair()

        assertThrows(TokenException::class.java) {
            JWTBuilder()
                .setSubject("test-subject")
                .sign(rsaKeyPair.public, JWTAlgorithm.HS256)
        }
    }

    @Test
    fun `test JWTBuilder sign rejects RSA algorithm with HMAC key`() {
        val hmacKey = generateHmacKey()

        assertThrows(TokenException::class.java) {
            JWTBuilder()
                .setSubject("test-subject")
                .sign(hmacKey, JWTAlgorithm.RS256)
        }
    }

    @Test
    fun `test algorithm confusion attack HMAC key used as RSA public key is rejected`() {
        // Simulate algorithm confusion: attacker signs with HMAC using the RSA public key bytes
        // The validator should reject this because key types don't match the algorithm
        val rsaKeyPair = generateRsaKeyPair()

        // Create a legitimate RSA token
        val token = JWTBuilder()
            .setSubject("admin")
            .sign(rsaKeyPair.private, JWTAlgorithm.RS256)

        // Validate with correct key and pinned algorithm — should pass
        assertTrue(JWTValidator.validate(token, rsaKeyPair.public, expectedAlgorithm = JWTAlgorithm.RS256))

        // If attacker re-signs with HS256 using public key material, the validator
        // should reject when expectedAlgorithm is pinned to RS256
        val hmacKey = generateHmacKey()
        val attackerToken = JWTBuilder()
            .setSubject("admin")
            .sign(hmacKey, JWTAlgorithm.HS256)

        assertThrows(TokenException::class.java) {
            JWTValidator.validate(attackerToken, rsaKeyPair.public, expectedAlgorithm = JWTAlgorithm.RS256)
        }
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
        assertTrue(JWTValidator.validate(token, keyPair.public, JWTAlgorithm.RS256))

        // Parse and verify claims
        val payload = JWTValidator.parse(token)
        assertEquals("test-service", payload.iss)
        assertEquals("user123", payload.sub)

        // Verify wrong key fails
        val wrongKeyPair = generateRsaKeyPair()
        assertFalse(JWTValidator.validate(token, wrongKeyPair.public, JWTAlgorithm.RS256))
    }
}
