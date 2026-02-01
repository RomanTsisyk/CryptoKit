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

/**
 * Integration tests demonstrating complete token management workflows.
 */
class TokenManagementIntegrationTest {

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
    fun `test complete authentication workflow with JWT`() {
        val key = generateHmacKey()
        val userId = "user123"
        val sessionId = SecureTokenGenerator.generateSessionId()

        // Step 1: User logs in, create JWT
        val token = JWTBuilder()
            .setIssuer("auth-service")
            .setSubject(userId)
            .setAudience("api-gateway")
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .addClaim("sessionId", sessionId)
            .addClaim("role", "user")
            .addClaim("permissions", listOf("read", "write"))
            .generateJwtId()
            .sign(key, JWTAlgorithm.HS256)

        assertNotNull(token)

        // Step 2: Validate token on subsequent requests
        assertTrue(JWTValidator.validate(token, key))
        assertFalse(JWTValidator.isExpired(token))

        // Step 3: Extract user information from token
        val payload = JWTValidator.parse(token)
        assertEquals(userId, payload.sub)
        assertEquals(sessionId, payload.customClaims["sessionId"])
        assertEquals("user", payload.customClaims["role"])

        // Step 4: Check specific permissions
        assertEquals("read", JWTValidator.getClaim(token, "permissions"))
    }

    @Test
    fun `test refresh token workflow`() {
        val key = generateHmacKey()
        val refreshToken = SecureTokenGenerator.generateRefreshToken()
        val userId = "user123"

        // Step 1: Create short-lived access token
        val accessToken = JWTBuilder()
            .setSubject(userId)
            .setExpiration(Date(System.currentTimeMillis() + 900000)) // 15 minutes
            .addClaim("type", "access")
            .sign(key, JWTAlgorithm.HS256)

        // Step 2: Validate access token
        assertTrue(JWTValidator.validate(accessToken, key))

        // Step 3: Simulate token refresh
        // In real scenario, refreshToken would be stored securely and validated
        val newAccessToken = JWTBuilder()
            .setSubject(userId)
            .setExpiration(Date(System.currentTimeMillis() + 900000))
            .addClaim("type", "access")
            .addClaim("refreshedFrom", refreshToken)
            .sign(key, JWTAlgorithm.HS256)

        assertTrue(JWTValidator.validate(newAccessToken, key))
        assertEquals("access", JWTValidator.getClaim(newAccessToken, "type"))
    }

    @Test
    fun `test API key generation and validation workflow`() {
        val apiKey = SecureTokenGenerator.generateApiKey()
        val csrfToken = SecureTokenGenerator.generateCsrfToken()

        assertNotNull(apiKey)
        assertNotNull(csrfToken)
        assertNotEquals(apiKey, csrfToken)

        // API keys should be long and secure
        assertTrue(apiKey.length >= 60)
        assertTrue(csrfToken.length >= 40)
    }

    @Test
    fun `test OTP generation for two-factor authentication`() {
        // Generate 6-digit OTP
        val otp = SecureTokenGenerator.generateNumericOTP(6)

        assertEquals(6, otp.length)
        assertTrue(otp.matches(Regex("^[0-9]{6}$")))

        // OTP should not start with 0
        assertNotEquals('0', otp[0])
    }

    @Test
    fun `test JWT with RSA for microservices`() {
        val keyPair = generateRsaKeyPair()
        val serviceId = "payment-service"

        // Service A creates a JWT signed with its private key
        val token = JWTBuilder()
            .setIssuer(serviceId)
            .setSubject("transaction-123")
            .setAudience("billing-service")
            .setExpiration(Date(System.currentTimeMillis() + 300000)) // 5 minutes
            .addClaim("amount", 99.99)
            .addClaim("currency", "USD")
            .sign(keyPair.private, JWTAlgorithm.RS256)

        // Service B validates the JWT using Service A's public key
        assertTrue(JWTValidator.validate(token, keyPair.public))

        val payload = JWTValidator.parse(token)
        assertEquals(serviceId, payload.iss)
        assertEquals("transaction-123", payload.sub)
        assertEquals("billing-service", payload.aud)
        assertEquals(99.99, payload.customClaims["amount"])
        assertEquals("USD", payload.customClaims["currency"])
    }

    @Test
    fun `test JWT expiration handling`() {
        val key = generateHmacKey()

        // Create an already expired token
        val expiredToken = JWTBuilder()
            .setSubject("user123")
            .setExpiration(Date(System.currentTimeMillis() - 1000)) // Expired 1 second ago
            .sign(key, JWTAlgorithm.HS256)

        // Signature is still valid
        assertTrue(JWTValidator.validate(expiredToken, key))

        // But token is expired
        assertTrue(JWTValidator.isExpired(expiredToken))

        // validateWithExpiry should throw exception
        assertThrows(TokenException::class.java) {
            JWTValidator.validateWithExpiry(expiredToken, key)
        }

        // Can allow expired tokens if needed
        assertTrue(JWTValidator.validateWithExpiry(expiredToken, key, allowExpired = true))
    }

    @Test
    fun `test JWT not before claim`() {
        val key = generateHmacKey()

        // Create a token that's not valid yet
        val futureToken = JWTBuilder()
            .setSubject("user123")
            .setNotBefore(Date(System.currentTimeMillis() + 60000)) // Valid in 1 minute
            .setExpiration(Date(System.currentTimeMillis() + 3600000))
            .sign(key, JWTAlgorithm.HS256)

        // Signature is valid
        assertTrue(JWTValidator.validate(futureToken, key))

        // But token is not yet valid
        val payload = JWTValidator.parse(futureToken)
        assertTrue(payload.isNotYetValid())

        // validateWithExpiry should throw exception
        assertThrows(TokenException::class.java) {
            JWTValidator.validateWithExpiry(futureToken, key)
        }
    }

    @Test
    fun `test multi-tenant JWT with different algorithms`() {
        val hmacKey = generateHmacKey()
        val rsaKeyPair = generateRsaKeyPair()

        // Tenant 1 uses HMAC
        val tenant1Token = JWTBuilder()
            .setIssuer("tenant1")
            .setSubject("user1")
            .addClaim("tenant", "tenant1")
            .sign(hmacKey, JWTAlgorithm.HS256)

        // Tenant 2 uses RSA
        val tenant2Token = JWTBuilder()
            .setIssuer("tenant2")
            .setSubject("user2")
            .addClaim("tenant", "tenant2")
            .sign(rsaKeyPair.private, JWTAlgorithm.RS256)

        // Validate each with appropriate key
        assertTrue(JWTValidator.validate(tenant1Token, hmacKey))
        assertTrue(JWTValidator.validate(tenant2Token, rsaKeyPair.public))

        // Check headers to determine algorithm
        val header1 = JWTValidator.parseHeader(tenant1Token)
        val header2 = JWTValidator.parseHeader(tenant2Token)

        assertEquals(JWTAlgorithm.HS256, header1.alg)
        assertEquals(JWTAlgorithm.RS256, header2.alg)
    }

    @Test
    fun `test secure token generation for various use cases`() {
        // Session ID for user sessions
        val sessionId = SecureTokenGenerator.generateSessionId()

        // API key for third-party integrations
        val apiKey = SecureTokenGenerator.generateApiKey()

        // Refresh token for OAuth
        val refreshToken = SecureTokenGenerator.generateRefreshToken()

        // CSRF token for form protection
        val csrfToken = SecureTokenGenerator.generateCsrfToken()

        // OTP for 2FA
        val otp = SecureTokenGenerator.generateNumericOTP()

        // Password reset token
        val resetToken = SecureTokenGenerator.generateAlphanumericToken(32)

        // All tokens should be unique
        val tokens = setOf(sessionId, apiKey, refreshToken, csrfToken, otp, resetToken)
        assertEquals(6, tokens.size)

        // Verify formats
        assertTrue(resetToken.matches(Regex("^[A-Za-z0-9]{32}$")))
        assertTrue(otp.matches(Regex("^[0-9]{6}$")))
        assertTrue(refreshToken.matches(Regex("^[0-9a-f]{128}$")))
    }

    @Test
    fun `test JWT with all claims and validation`() {
        val key = generateHmacKey()
        val now = System.currentTimeMillis()

        val token = JWTBuilder()
            .setIssuer("auth-server")
            .setSubject("user@example.com")
            .setAudience("api.example.com")
            .setIssuedAt(Date(now))
            .setExpiration(Date(now + 3600000))
            .setNotBefore(Date(now))
            .generateJwtId()
            .addClaim("email", "user@example.com")
            .addClaim("verified", true)
            .addClaim("roles", listOf("user", "admin"))
            .sign(key, JWTAlgorithm.HS256)

        // Full validation
        assertTrue(JWTValidator.validateWithExpiry(token, key))

        // Verify all claims
        val allClaims = JWTValidator.getAllClaims(token)
        assertEquals("auth-server", allClaims["iss"])
        assertEquals("user@example.com", allClaims["sub"])
        assertEquals("api.example.com", allClaims["aud"])
        assertEquals("user@example.com", allClaims["email"])
        assertEquals(true, allClaims["verified"])
        assertNotNull(allClaims["jti"])
    }

    @Test
    fun `test tampered JWT detection`() {
        val key = generateHmacKey()

        val token = JWTBuilder()
            .setSubject("user123")
            .addClaim("role", "user")
            .sign(key, JWTAlgorithm.HS256)

        // Tamper with the token by changing a character in the payload
        val parts = token.split(".")
        val tamperedToken = "${parts[0]}.${parts[1].dropLast(1)}X.${parts[2]}"

        // Validation should fail
        assertFalse(JWTValidator.validate(tamperedToken, key))
    }

    private fun assertNotEquals(expected: Any?, actual: Any?) {
        assertFalse(expected == actual)
    }
}
