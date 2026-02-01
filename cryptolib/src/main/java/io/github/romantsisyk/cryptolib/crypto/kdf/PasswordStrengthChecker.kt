package io.github.romantsisyk.cryptolib.crypto.kdf

/**
 * Utility object for checking password strength and validating password requirements.
 * Provides methods to assess password security and ensure compliance with security policies.
 */
object PasswordStrengthChecker {

    // Common weak passwords that should be avoided
    private val COMMON_PASSWORDS = setOf(
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "111111", "iloveyou", "master",
        "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football"
    )

    /**
     * Checks the strength of a password and returns a strength level.
     * The assessment is based on length, character variety, and common password checks.
     *
     * @param password The password to check.
     * @return The [PasswordStrength] level of the password.
     */
    @JvmStatic
    fun checkStrength(password: String): PasswordStrength {
        if (password.isEmpty()) {
            return PasswordStrength.WEAK
        }

        // Check against common weak passwords
        if (COMMON_PASSWORDS.contains(password.lowercase())) {
            return PasswordStrength.WEAK
        }

        val length = password.length
        val hasLowercase = password.any { it.isLowerCase() }
        val hasUppercase = password.any { it.isUpperCase() }
        val hasDigit = password.any { it.isDigit() }
        val hasSpecial = password.any { !it.isLetterOrDigit() }

        // Count character types present
        val charTypeCount = listOf(hasLowercase, hasUppercase, hasDigit, hasSpecial).count { it }

        // Calculate score based on various criteria
        var score = 0

        // Length scoring
        when {
            length >= 16 -> score += 3
            length >= 12 -> score += 2
            length >= 8 -> score += 1
        }

        // Character variety scoring
        score += charTypeCount

        // Bonus for mixing many character types with good length
        if (charTypeCount >= 3 && length >= 12) {
            score += 1
        }

        if (charTypeCount == 4 && length >= 16) {
            score += 1
        }

        // Check for sequential or repeated characters (weakness)
        if (hasSequentialChars(password) || hasRepeatedChars(password)) {
            score -= 1
        }

        // Determine strength level based on score
        return when {
            score <= 2 -> PasswordStrength.WEAK
            score <= 4 -> PasswordStrength.FAIR
            score <= 6 -> PasswordStrength.STRONG
            else -> PasswordStrength.VERY_STRONG
        }
    }

    /**
     * Checks if a password meets minimum requirements.
     *
     * @param password The password to validate.
     * @param minLength Minimum required length (default: 8).
     * @param requireUppercase Whether uppercase letters are required (default: true).
     * @param requireDigit Whether digits are required (default: true).
     * @param requireSpecial Whether special characters are required (default: true).
     * @return True if the password meets all requirements, false otherwise.
     */
    @JvmStatic
    @JvmOverloads
    fun meetsMinimumRequirements(
        password: String,
        minLength: Int = 8,
        requireUppercase: Boolean = true,
        requireDigit: Boolean = true,
        requireSpecial: Boolean = true
    ): Boolean {
        if (password.length < minLength) {
            return false
        }

        if (requireUppercase && !password.any { it.isUpperCase() }) {
            return false
        }

        if (requireDigit && !password.any { it.isDigit() }) {
            return false
        }

        if (requireSpecial && !password.any { !it.isLetterOrDigit() }) {
            return false
        }

        // Must have at least lowercase letters
        if (!password.any { it.isLowerCase() }) {
            return false
        }

        return true
    }

    /**
     * Checks for sequential characters in a password (e.g., "abc", "123").
     *
     * @param password The password to check.
     * @return True if sequential characters are found, false otherwise.
     */
    private fun hasSequentialChars(password: String): Boolean {
        if (password.length < 3) return false

        for (i in 0 until password.length - 2) {
            val first = password[i].code
            val second = password[i + 1].code
            val third = password[i + 2].code

            // Check for ascending or descending sequences
            if ((second == first + 1 && third == second + 1) ||
                (second == first - 1 && third == second - 1)) {
                return true
            }
        }
        return false
    }

    /**
     * Checks for repeated characters in a password (e.g., "aaa", "111").
     *
     * @param password The password to check.
     * @return True if repeated characters are found, false otherwise.
     */
    private fun hasRepeatedChars(password: String): Boolean {
        if (password.length < 3) return false

        for (i in 0 until password.length - 2) {
            if (password[i] == password[i + 1] && password[i] == password[i + 2]) {
                return true
            }
        }
        return false
    }

    /**
     * Validates password requirements and returns a list of validation errors.
     * If the list is empty, the password is valid.
     *
     * @param password The password to validate.
     * @param minLength Minimum required length (default: 8).
     * @param requireUppercase Whether uppercase letters are required (default: true).
     * @param requireDigit Whether digits are required (default: true).
     * @param requireSpecial Whether special characters are required (default: true).
     * @return A list of validation error messages. Empty if password is valid.
     */
    @JvmStatic
    @JvmOverloads
    fun validatePassword(
        password: String,
        minLength: Int = 8,
        requireUppercase: Boolean = true,
        requireDigit: Boolean = true,
        requireSpecial: Boolean = true
    ): List<String> {
        val errors = mutableListOf<String>()

        if (password.length < minLength) {
            errors.add("Password must be at least $minLength characters long")
        }

        if (!password.any { it.isLowerCase() }) {
            errors.add("Password must contain at least one lowercase letter")
        }

        if (requireUppercase && !password.any { it.isUpperCase() }) {
            errors.add("Password must contain at least one uppercase letter")
        }

        if (requireDigit && !password.any { it.isDigit() }) {
            errors.add("Password must contain at least one digit")
        }

        if (requireSpecial && !password.any { !it.isLetterOrDigit() }) {
            errors.add("Password must contain at least one special character")
        }

        if (COMMON_PASSWORDS.contains(password.lowercase())) {
            errors.add("Password is too common and easily guessable")
        }

        if (hasSequentialChars(password)) {
            errors.add("Password contains sequential characters which makes it weaker")
        }

        if (hasRepeatedChars(password)) {
            errors.add("Password contains repeated characters which makes it weaker")
        }

        return errors
    }
}
