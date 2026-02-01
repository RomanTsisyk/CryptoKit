package io.github.romantsisyk.cryptolib.crypto.kdf

/**
 * Enum representing password strength levels.
 */
enum class PasswordStrength {
    /**
     * Weak password - easily guessable or too short.
     */
    WEAK,

    /**
     * Fair password - meets basic requirements but could be stronger.
     */
    FAIR,

    /**
     * Strong password - meets good security requirements.
     */
    STRONG,

    /**
     * Very strong password - exceeds security requirements with high complexity.
     */
    VERY_STRONG
}
