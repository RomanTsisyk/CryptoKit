package io.github.romantsisyk.cryptolib.certificates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidationResultTest {

    @Test
    fun `test ValidationResult creation with all fields`() {
        val errors = listOf("Error 1", "Error 2")
        val warnings = listOf("Warning 1", "Warning 2")

        val result = ValidationResult(
            isValid = false,
            errors = errors,
            warnings = warnings
        )

        assertFalse(result.isValid)
        assertEquals(errors, result.errors)
        assertEquals(warnings, result.warnings)
    }

    @Test
    fun `test ValidationResult success factory method`() {
        val result = ValidationResult.success()

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
        assertTrue(result.warnings.isEmpty())
    }

    @Test
    fun `test ValidationResult success with warnings`() {
        val warnings = listOf("Warning 1", "Warning 2")
        val result = ValidationResult.success(warnings)

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
        assertEquals(warnings, result.warnings)
    }

    @Test
    fun `test ValidationResult failure factory method`() {
        val errors = listOf("Error 1", "Error 2")
        val result = ValidationResult.failure(errors)

        assertFalse(result.isValid)
        assertEquals(errors, result.errors)
        assertTrue(result.warnings.isEmpty())
    }

    @Test
    fun `test ValidationResult failure with warnings`() {
        val errors = listOf("Error 1")
        val warnings = listOf("Warning 1", "Warning 2")
        val result = ValidationResult.failure(errors, warnings)

        assertFalse(result.isValid)
        assertEquals(errors, result.errors)
        assertEquals(warnings, result.warnings)
    }

    @Test
    fun `test ValidationResult with empty errors and warnings`() {
        val result = ValidationResult(
            isValid = true,
            errors = emptyList(),
            warnings = emptyList()
        )

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
        assertTrue(result.warnings.isEmpty())
    }

    @Test
    fun `test ValidationResult equality`() {
        val result1 = ValidationResult(
            isValid = true,
            errors = listOf("Error"),
            warnings = listOf("Warning")
        )

        val result2 = ValidationResult(
            isValid = true,
            errors = listOf("Error"),
            warnings = listOf("Warning")
        )

        assertEquals(result1, result2)
        assertEquals(result1.hashCode(), result2.hashCode())
    }

    @Test
    fun `test ValidationResult copy method`() {
        val original = ValidationResult(
            isValid = false,
            errors = listOf("Error 1"),
            warnings = listOf("Warning 1")
        )

        val modified = original.copy(isValid = true, errors = emptyList())

        assertTrue(modified.isValid)
        assertTrue(modified.errors.isEmpty())
        assertEquals(original.warnings, modified.warnings)
    }

    @Test
    fun `test ValidationResult toString contains all fields`() {
        val result = ValidationResult(
            isValid = false,
            errors = listOf("Test Error"),
            warnings = listOf("Test Warning")
        )

        val toString = result.toString()

        assertTrue(toString.contains("false") || toString.contains("isValid"))
        assertTrue(toString.contains("Test Error"))
        assertTrue(toString.contains("Test Warning"))
    }

    @Test
    fun `test multiple errors in ValidationResult`() {
        val errors = listOf(
            "Certificate has expired",
            "Invalid signature",
            "Untrusted issuer"
        )

        val result = ValidationResult.failure(errors)

        assertFalse(result.isValid)
        assertEquals(3, result.errors.size)
        assertTrue(result.errors.contains("Certificate has expired"))
        assertTrue(result.errors.contains("Invalid signature"))
        assertTrue(result.errors.contains("Untrusted issuer"))
    }

    @Test
    fun `test multiple warnings in ValidationResult`() {
        val warnings = listOf(
            "Certificate will expire in 30 days",
            "Weak signature algorithm",
            "Missing key usage extension"
        )

        val result = ValidationResult.success(warnings)

        assertTrue(result.isValid)
        assertEquals(3, result.warnings.size)
        assertTrue(result.warnings.contains("Certificate will expire in 30 days"))
        assertTrue(result.warnings.contains("Weak signature algorithm"))
        assertTrue(result.warnings.contains("Missing key usage extension"))
    }

    @Test
    fun `test ValidationResult with both errors and warnings`() {
        val errors = listOf("Critical error")
        val warnings = listOf("Minor warning")

        val result = ValidationResult(
            isValid = false,
            errors = errors,
            warnings = warnings
        )

        assertFalse(result.isValid)
        assertEquals(1, result.errors.size)
        assertEquals(1, result.warnings.size)
    }
}
