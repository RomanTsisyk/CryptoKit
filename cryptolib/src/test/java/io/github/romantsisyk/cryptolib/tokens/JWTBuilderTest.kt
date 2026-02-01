package io.github.romantsisyk.cryptolib.tokens

import io.github.romantsisyk.cryptolib.exceptions.TokenException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.util.Date
import javax.crypto.KeyGenerator

class JWTBuilderTest {

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
    fun `test builder with issuer`() {
        val payload = JWTBuilder()
            .setIssuer("test-issuer")
            .build()

        assertEquals("test-issuer", payload.iss)
    }

    @Test
    fun `test builder with subject`() {
        val payload = JWTBuilder()
            .setSubject("test-subject")
            .build()

        assertEquals("test-subject", payload.sub)
    }

    @Test
    fun `test builder with audience`() {
        val payload = JWTBuilder()
            .setAudience("test-audience")
            .build()

        assertEquals("test-audience", payload.aud)
    }

    @Test
    fun `test builder with expiration using Date`() {
        val expirationDate = Date(System.currentTimeMillis() + 3600000)
        val payload = JWTBuilder()
            .setExpiration(expirationDate)
            .build()

        assertEquals(expirationDate.time / 1000, payload.exp)
    }

    @Test
    fun `test builder with expiration using seconds`() {
        val expirationSeconds = 1234567890L
        val payload = JWTBuilder()
            .setExpirationSeconds(expirationSeconds)
            .build()

        assertEquals(expirationSeconds, payload.exp)
    }

    @Test
    fun `test builder with issued at using Date`() {
        val issuedAtDate = Date()
        val payload = JWTBuilder()
            .setIssuedAt(issuedAtDate)
            .build()

        assertEquals(issuedAtDate.time / 1000, payload.iat)
    }

    @Test
    fun `test builder with issued at using seconds`() {
        val issuedAtSeconds = 1234567890L
        val payload = JWTBuilder()
            .setIssuedAtSeconds(issuedAtSeconds)
            .build()

        assertEquals(issuedAtSeconds, payload.iat)
    }

    @Test
    fun `test builder with not before using Date`() {
        val notBeforeDate = Date()
        val payload = JWTBuilder()
            .setNotBefore(notBeforeDate)
            .build()

        assertEquals(notBeforeDate.time / 1000, payload.nbf)
    }

    @Test
    fun `test builder with not before using seconds`() {
        val notBeforeSeconds = 1234567890L
        val payload = JWTBuilder()
            .setNotBeforeSeconds(notBeforeSeconds)
            .build()

        assertEquals(notBeforeSeconds, payload.nbf)
    }

    @Test
    fun `test builder with JWT ID`() {
        val payload = JWTBuilder()
            .setJwtId("test-jwt-id")
            .build()

        assertEquals("test-jwt-id", payload.jti)
    }

    @Test
    fun `test builder generates random JWT ID`() {
        val payload = JWTBuilder()
            .generateJwtId()
            .build()

        assertNotNull(payload.jti)
        assertTrue(payload.jti!!.isNotEmpty())
    }

    @Test
    fun `test builder with custom claims`() {
        val payload = JWTBuilder()
            .addClaim("userId", "12345")
            .addClaim("role", "admin")
            .build()

        assertEquals("12345", payload.customClaims["userId"])
        assertEquals("admin", payload.customClaims["role"])
    }

    @Test
    fun `test builder prevents overwriting standard claims`() {
        assertThrows(IllegalArgumentException::class.java) {
            JWTBuilder().addClaim("iss", "value")
        }

        assertThrows(IllegalArgumentException::class.java) {
            JWTBuilder().addClaim("sub", "value")
        }

        assertThrows(IllegalArgumentException::class.java) {
            JWTBuilder().addClaim("exp", 123456)
        }
    }

    @Test
    fun `test builder with all claims`() {
        val payload = JWTBuilder()
            .setIssuer("issuer")
            .setSubject("subject")
            .setAudience("audience")
            .setExpirationSeconds(1234567890L)
            .setIssuedAtSeconds(1234567800L)
            .setNotBeforeSeconds(1234567810L)
            .setJwtId("jwt-id")
            .addClaim("customKey", "customValue")
            .build()

        assertEquals("issuer", payload.iss)
        assertEquals("subject", payload.sub)
        assertEquals("audience", payload.aud)
        assertEquals(1234567890L, payload.exp)
        assertEquals(1234567800L, payload.iat)
        assertEquals(1234567810L, payload.nbf)
        assertEquals("jwt-id", payload.jti)
        assertEquals("customValue", payload.customClaims["customKey"])
    }

    @Test
    fun `test sign with HMAC HS256 produces valid JWT`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setIssuedAt(Date())
            .sign(key, JWTAlgorithm.HS256)

        assertNotNull(token)
        val parts = token.split(".")
        assertEquals(3, parts.size)
    }

    @Test
    fun `test sign with HMAC HS384 produces valid JWT`() {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA384")
        keyGenerator.init(384)
        val key = keyGenerator.generateKey()

        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS384)

        assertNotNull(token)
        val parts = token.split(".")
        assertEquals(3, parts.size)
    }

    @Test
    fun `test sign with HMAC HS512 produces valid JWT`() {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA512")
        keyGenerator.init(512)
        val key = keyGenerator.generateKey()

        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(key, JWTAlgorithm.HS512)

        assertNotNull(token)
        val parts = token.split(".")
        assertEquals(3, parts.size)
    }

    @Test
    fun `test sign with RSA RS256 produces valid JWT`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .setIssuedAt(Date())
            .sign(keyPair.private, JWTAlgorithm.RS256)

        assertNotNull(token)
        val parts = token.split(".")
        assertEquals(3, parts.size)
    }

    @Test
    fun `test sign with RSA RS384 produces valid JWT`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS384)

        assertNotNull(token)
        val parts = token.split(".")
        assertEquals(3, parts.size)
    }

    @Test
    fun `test sign with RSA RS512 produces valid JWT`() {
        val keyPair = generateRsaKeyPair()
        val token = JWTBuilder()
            .setSubject("test-subject")
            .sign(keyPair.private, JWTAlgorithm.RS512)

        assertNotNull(token)
        val parts = token.split(".")
        assertEquals(3, parts.size)
    }

    @Test
    fun `test builder chaining`() {
        val key = generateHmacKey()
        val token = JWTBuilder()
            .setIssuer("issuer")
            .setSubject("subject")
            .setAudience("audience")
            .addClaim("role", "admin")
            .generateJwtId()
            .sign(key, JWTAlgorithm.HS256)

        assertNotNull(token)
        assertTrue(token.isNotEmpty())
    }

    @Test
    fun `test multiple builders are independent`() {
        val builder1 = JWTBuilder().setIssuer("issuer1")
        val builder2 = JWTBuilder().setIssuer("issuer2")

        val payload1 = builder1.build()
        val payload2 = builder2.build()

        assertEquals("issuer1", payload1.iss)
        assertEquals("issuer2", payload2.iss)
    }
}
