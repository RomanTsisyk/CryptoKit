package io.github.romantsisyk.cryptolib.tokens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JWTHeaderTest {

    @Test
    fun `test JWTHeader creation with default type`() {
        val header = JWTHeader(alg = JWTAlgorithm.HS256)
        assertEquals(JWTAlgorithm.HS256, header.alg)
        assertEquals("JWT", header.typ)
    }

    @Test
    fun `test JWTHeader creation with custom type`() {
        val header = JWTHeader(alg = JWTAlgorithm.RS256, typ = "CustomType")
        assertEquals(JWTAlgorithm.RS256, header.alg)
        assertEquals("CustomType", header.typ)
    }

    @Test
    fun `test JWTHeader toJson`() {
        val header = JWTHeader(alg = JWTAlgorithm.HS256)
        val json = header.toJson()

        assertTrue(json.contains("\"alg\":\"HS256\""))
        assertTrue(json.contains("\"typ\":\"JWT\""))
    }

    @Test
    fun `test JWTHeader fromJson with valid JSON`() {
        val json = """{"alg":"HS256","typ":"JWT"}"""
        val header = JWTHeader.fromJson(json)

        assertEquals(JWTAlgorithm.HS256, header.alg)
        assertEquals("JWT", header.typ)
    }

    @Test
    fun `test JWTHeader fromJson with missing type defaults to JWT`() {
        val json = """{"alg":"RS512"}"""
        val header = JWTHeader.fromJson(json)

        assertEquals(JWTAlgorithm.RS512, header.alg)
        assertEquals("JWT", header.typ)
    }

    @Test
    fun `test JWTHeader fromJson with missing alg throws exception`() {
        val json = """{"typ":"JWT"}"""

        assertThrows(IllegalArgumentException::class.java) {
            JWTHeader.fromJson(json)
        }
    }

    @Test
    fun `test JWTHeader fromJson with invalid algorithm throws exception`() {
        val json = """{"alg":"INVALID","typ":"JWT"}"""

        assertThrows(IllegalArgumentException::class.java) {
            JWTHeader.fromJson(json)
        }
    }

    @Test
    fun `test JWTHeader roundtrip serialization`() {
        val original = JWTHeader(alg = JWTAlgorithm.RS384, typ = "CustomJWT")
        val json = original.toJson()
        val deserialized = JWTHeader.fromJson(json)

        assertEquals(original.alg, deserialized.alg)
        assertEquals(original.typ, deserialized.typ)
    }
}
