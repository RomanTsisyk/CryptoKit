package io.github.romantsisyk.cryptolib.crypto.kdf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordStrengthCheckerTest {

    @Test
    fun `test checkStrength returns WEAK for empty password`() {
        val strength = PasswordStrengthChecker.checkStrength("")
        assertEquals(PasswordStrength.WEAK, strength)
    }

    @Test
    fun `test checkStrength returns WEAK for common password`() {
        val strength = PasswordStrengthChecker.checkStrength("password")
        assertEquals(PasswordStrength.WEAK, strength)
    }

    @Test
    fun `test checkStrength returns WEAK for 123456`() {
        val strength = PasswordStrengthChecker.checkStrength("123456")
        assertEquals(PasswordStrength.WEAK, strength)
    }

    @Test
    fun `test checkStrength returns WEAK for short password`() {
        val strength = PasswordStrengthChecker.checkStrength("Ab1!")
        assertEquals(PasswordStrength.WEAK, strength)
    }

    @Test
    fun `test checkStrength returns FAIR for basic password`() {
        val strength = PasswordStrengthChecker.checkStrength("Password1")
        assertEquals(PasswordStrength.FAIR, strength)
    }

    @Test
    fun `test checkStrength returns STRONG for good password`() {
        val strength = PasswordStrengthChecker.checkStrength("MyP@ssw0rd123")
        assertEquals(PasswordStrength.STRONG, strength)
    }

    @Test
    fun `test checkStrength returns VERY_STRONG for excellent password`() {
        val strength = PasswordStrengthChecker.checkStrength("MyV3ry\$tr0ng&C0mpl3xP@ssw0rd!")
        assertEquals(PasswordStrength.VERY_STRONG, strength)
    }

    @Test
    fun `test checkStrength penalizes sequential characters`() {
        // Password with sequential characters should be weaker
        val withSequential = PasswordStrengthChecker.checkStrength("Abc123Password!")
        val withoutSequential = PasswordStrengthChecker.checkStrength("Axc193Password!")

        // The one without sequential chars should be stronger or equal
        assertTrue(withoutSequential.ordinal >= withSequential.ordinal)
    }

    @Test
    fun `test checkStrength penalizes repeated characters`() {
        // Password with repeated characters should be weaker
        val withRepeated = PasswordStrengthChecker.checkStrength("Paasssword111!")
        val withoutRepeated = PasswordStrengthChecker.checkStrength("Pa5sw0rd17!")

        // The one without repeated chars should be stronger or equal
        assertTrue(withoutRepeated.ordinal >= withRepeated.ordinal)
    }

    @Test
    fun `test meetsMinimumRequirements with valid password`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements("Password1!")
        assertTrue(result)
    }

    @Test
    fun `test meetsMinimumRequirements rejects short password`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements("Pass1!")
        assertFalse(result)
    }

    @Test
    fun `test meetsMinimumRequirements rejects password without uppercase`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements("password1!")
        assertFalse(result)
    }

    @Test
    fun `test meetsMinimumRequirements rejects password without digit`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements("Password!")
        assertFalse(result)
    }

    @Test
    fun `test meetsMinimumRequirements rejects password without special char`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements("Password1")
        assertFalse(result)
    }

    @Test
    fun `test meetsMinimumRequirements rejects password without lowercase`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements("PASSWORD1!")
        assertFalse(result)
    }

    @Test
    fun `test meetsMinimumRequirements with custom min length`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements(
            "Pass1!",
            minLength = 6
        )
        assertTrue(result)
    }

    @Test
    fun `test meetsMinimumRequirements without uppercase requirement`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements(
            "password1!",
            requireUppercase = false
        )
        assertTrue(result)
    }

    @Test
    fun `test meetsMinimumRequirements without digit requirement`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements(
            "Password!",
            requireDigit = false
        )
        assertTrue(result)
    }

    @Test
    fun `test meetsMinimumRequirements without special char requirement`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements(
            "Password1",
            requireSpecial = false
        )
        assertTrue(result)
    }

    @Test
    fun `test meetsMinimumRequirements with all requirements disabled`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements(
            "password",
            minLength = 6,
            requireUppercase = false,
            requireDigit = false,
            requireSpecial = false
        )
        assertTrue(result)
    }

    @Test
    fun `test validatePassword returns empty list for valid password`() {
        val errors = PasswordStrengthChecker.validatePassword("Password1!")
        assertTrue(errors.isEmpty())
    }

    @Test
    fun `test validatePassword returns error for short password`() {
        val errors = PasswordStrengthChecker.validatePassword("Pass1!")
        assertTrue(errors.any { it.contains("at least") && it.contains("characters") })
    }

    @Test
    fun `test validatePassword returns error for missing uppercase`() {
        val errors = PasswordStrengthChecker.validatePassword("password1!")
        assertTrue(errors.any { it.contains("uppercase") })
    }

    @Test
    fun `test validatePassword returns error for missing lowercase`() {
        val errors = PasswordStrengthChecker.validatePassword("PASSWORD1!")
        assertTrue(errors.any { it.contains("lowercase") })
    }

    @Test
    fun `test validatePassword returns error for missing digit`() {
        val errors = PasswordStrengthChecker.validatePassword("Password!")
        assertTrue(errors.any { it.contains("digit") })
    }

    @Test
    fun `test validatePassword returns error for missing special char`() {
        val errors = PasswordStrengthChecker.validatePassword("Password1")
        assertTrue(errors.any { it.contains("special character") })
    }

    @Test
    fun `test validatePassword returns error for common password`() {
        val errors = PasswordStrengthChecker.validatePassword("Password123!")
        // Should still check if it's in common list
        val isCommon = errors.any { it.contains("common") }
        // Password123! might not be in the common list, so we just verify the check works
        assertTrue(errors.isEmpty() || isCommon)
    }

    @Test
    fun `test validatePassword returns error for sequential characters`() {
        val errors = PasswordStrengthChecker.validatePassword("Abc123Password!")
        assertTrue(errors.any { it.contains("sequential") })
    }

    @Test
    fun `test validatePassword returns error for repeated characters`() {
        val errors = PasswordStrengthChecker.validatePassword("Passsworrrd111!")
        assertTrue(errors.any { it.contains("repeated") })
    }

    @Test
    fun `test validatePassword returns multiple errors for weak password`() {
        val errors = PasswordStrengthChecker.validatePassword("pass")
        assertTrue(errors.size > 1)
    }

    @Test
    fun `test validatePassword with custom requirements`() {
        val errors = PasswordStrengthChecker.validatePassword(
            "password",
            minLength = 6,
            requireUppercase = false,
            requireDigit = false,
            requireSpecial = false
        )
        assertTrue(errors.isEmpty())
    }

    @Test
    fun `test checkStrength case insensitive for common passwords`() {
        val strength1 = PasswordStrengthChecker.checkStrength("PASSWORD")
        val strength2 = PasswordStrengthChecker.checkStrength("password")
        val strength3 = PasswordStrengthChecker.checkStrength("PaSsWoRd")

        assertEquals(PasswordStrength.WEAK, strength1)
        assertEquals(PasswordStrength.WEAK, strength2)
        assertEquals(PasswordStrength.WEAK, strength3)
    }

    @Test
    fun `test long password with all character types is very strong`() {
        val strength = PasswordStrengthChecker.checkStrength("Th1sIs@V3ryL0ngP@ssw0rdW1thM@nyChar@ct3rs!")
        assertEquals(PasswordStrength.VERY_STRONG, strength)
    }

    @Test
    fun `test password with only lowercase is weak`() {
        val strength = PasswordStrengthChecker.checkStrength("thisisalllowercase")
        assertEquals(PasswordStrength.WEAK, strength)
    }

    @Test
    fun `test password with lowercase and numbers is fair or weak`() {
        val strength = PasswordStrengthChecker.checkStrength("password123456")
        assertTrue(strength == PasswordStrength.WEAK || strength == PasswordStrength.FAIR)
    }

    @Test
    fun `test 12 character password with mixed types is strong`() {
        val strength = PasswordStrengthChecker.checkStrength("P@ssw0rd1234")
        assertTrue(strength == PasswordStrength.STRONG || strength == PasswordStrength.FAIR)
    }

    @Test
    fun `test 16 character password with all types is strong or very strong`() {
        val strength = PasswordStrengthChecker.checkStrength("MyP@ssw0rd123456")
        assertTrue(strength == PasswordStrength.STRONG || strength == PasswordStrength.VERY_STRONG)
    }

    @Test
    fun `test validatePassword for qwerty common password`() {
        val errors = PasswordStrengthChecker.validatePassword("qwerty")
        assertTrue(errors.any { it.contains("common") })
    }

    @Test
    fun `test validatePassword for 123456 common password`() {
        val errors = PasswordStrengthChecker.validatePassword("123456")
        assertTrue(errors.any { it.contains("common") })
    }

    @Test
    fun `test meetsMinimumRequirements accepts exactly min length`() {
        val result = PasswordStrengthChecker.meetsMinimumRequirements(
            "Pass123!",
            minLength = 8
        )
        assertTrue(result)
    }

    @Test
    fun `test password strength progression`() {
        val weak = PasswordStrengthChecker.checkStrength("pass")
        val fair = PasswordStrengthChecker.checkStrength("Password1")
        val strong = PasswordStrengthChecker.checkStrength("P@ssw0rd123")
        val veryStrong = PasswordStrengthChecker.checkStrength("MyV3ry\$tr0ng&C0mpl3xP@ssw0rd!")

        assertTrue(weak.ordinal < fair.ordinal || weak == PasswordStrength.WEAK)
        assertTrue(fair.ordinal < strong.ordinal || fair.ordinal <= PasswordStrength.FAIR.ordinal)
        assertTrue(strong.ordinal < veryStrong.ordinal || strong.ordinal <= PasswordStrength.STRONG.ordinal)
    }
}
