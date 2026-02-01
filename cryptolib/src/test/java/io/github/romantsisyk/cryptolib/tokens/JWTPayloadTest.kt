package io.github.romantsisyk.cryptolib.tokens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JWTPayloadTest {

    @Test
    fun `test JWTPayload creation with all standard claims`() {
        val payload = JWTPayload(
            iss = "test-issuer",
            sub = "test-subject",
            aud = "test-audience",
            exp = 1234567890L,
            iat = 1234567800L,
            nbf = 1234567810L,
            jti = "test-jwt-id"
        )

        assertEquals("test-issuer", payload.iss)
        assertEquals("test-subject", payload.sub)
        assertEquals("test-audience", payload.aud)
        assertEquals(1234567890L, payload.exp)
        assertEquals(1234567800L, payload.iat)
        assertEquals(1234567810L, payload.nbf)
        assertEquals("test-jwt-id", payload.jti)
    }

    @Test
    fun `test JWTPayload with custom claims`() {
        val customClaims = mapOf(
            "userId" to "12345",
            "role" to "admin",
            "permissions" to listOf("read", "write")
        )

        val payload = JWTPayload(
            sub = "test-subject",
            customClaims = customClaims
        )

        assertEquals("test-subject", payload.sub)
        assertEquals("12345", payload.customClaims["userId"])
        assertEquals("admin", payload.customClaims["role"])
    }

    @Test
    fun `test JWTPayload toJson includes all claims`() {
        val payload = JWTPayload(
            iss = "issuer",
            sub = "subject",
            exp = 1234567890L,
            customClaims = mapOf("customKey" to "customValue")
        )

        val json = payload.toJson()

        assertTrue(json.contains("\"iss\":\"issuer\""))
        assertTrue(json.contains("\"sub\":\"subject\""))
        assertTrue(json.contains("\"exp\":1234567890"))
        assertTrue(json.contains("\"customKey\":\"customValue\""))
    }

    @Test
    fun `test JWTPayload fromJson with standard claims`() {
        val json = """
            {
                "iss": "test-issuer",
                "sub": "test-subject",
                "aud": "test-audience",
                "exp": 1234567890,
                "iat": 1234567800,
                "nbf": 1234567810,
                "jti": "test-id"
            }
        """.trimIndent()

        val payload = JWTPayload.fromJson(json)

        assertEquals("test-issuer", payload.iss)
        assertEquals("test-subject", payload.sub)
        assertEquals("test-audience", payload.aud)
        assertEquals(1234567890L, payload.exp)
        assertEquals(1234567800L, payload.iat)
        assertEquals(1234567810L, payload.nbf)
        assertEquals("test-id", payload.jti)
    }

    @Test
    fun `test JWTPayload fromJson with custom claims`() {
        val json = """
            {
                "sub": "subject",
                "customKey": "customValue",
                "numericKey": 42
            }
        """.trimIndent()

        val payload = JWTPayload.fromJson(json)

        assertEquals("subject", payload.sub)
        assertEquals("customValue", payload.customClaims["customKey"])
        assertEquals(42, payload.customClaims["numericKey"])
    }

    @Test
    fun `test JWTPayload isExpired returns true for expired token`() {
        val currentTime = System.currentTimeMillis()
        val expiredTime = (currentTime / 1000) - 3600 // 1 hour ago

        val payload = JWTPayload(exp = expiredTime)

        assertTrue(payload.isExpired(currentTime))
    }

    @Test
    fun `test JWTPayload isExpired returns false for valid token`() {
        val currentTime = System.currentTimeMillis()
        val futureTime = (currentTime / 1000) + 3600 // 1 hour from now

        val payload = JWTPayload(exp = futureTime)

        assertFalse(payload.isExpired(currentTime))
    }

    @Test
    fun `test JWTPayload isExpired returns false when exp is null`() {
        val payload = JWTPayload()

        assertFalse(payload.isExpired())
    }

    @Test
    fun `test JWTPayload isNotYetValid returns true when nbf is in future`() {
        val currentTime = System.currentTimeMillis()
        val futureTime = (currentTime / 1000) + 3600 // 1 hour from now

        val payload = JWTPayload(nbf = futureTime)

        assertTrue(payload.isNotYetValid(currentTime))
    }

    @Test
    fun `test JWTPayload isNotYetValid returns false when nbf is in past`() {
        val currentTime = System.currentTimeMillis()
        val pastTime = (currentTime / 1000) - 3600 // 1 hour ago

        val payload = JWTPayload(nbf = pastTime)

        assertFalse(payload.isNotYetValid(currentTime))
    }

    @Test
    fun `test JWTPayload isNotYetValid returns false when nbf is null`() {
        val payload = JWTPayload()

        assertFalse(payload.isNotYetValid())
    }

    @Test
    fun `test JWTPayload roundtrip serialization`() {
        val original = JWTPayload(
            iss = "issuer",
            sub = "subject",
            aud = "audience",
            exp = 1234567890L,
            iat = 1234567800L,
            customClaims = mapOf("key" to "value")
        )

        val json = original.toJson()
        val deserialized = JWTPayload.fromJson(json)

        assertEquals(original.iss, deserialized.iss)
        assertEquals(original.sub, deserialized.sub)
        assertEquals(original.aud, deserialized.aud)
        assertEquals(original.exp, deserialized.exp)
        assertEquals(original.iat, deserialized.iat)
        assertEquals(original.customClaims["key"], deserialized.customClaims["key"])
    }

    @Test
    fun `test JWTPayload with minimal claims`() {
        val json = """{"sub": "subject"}"""
        val payload = JWTPayload.fromJson(json)

        assertEquals("subject", payload.sub)
        assertNull(payload.iss)
        assertNull(payload.aud)
        assertNull(payload.exp)
        assertNull(payload.iat)
        assertNull(payload.nbf)
        assertNull(payload.jti)
        assertTrue(payload.customClaims.isEmpty())
    }
}
