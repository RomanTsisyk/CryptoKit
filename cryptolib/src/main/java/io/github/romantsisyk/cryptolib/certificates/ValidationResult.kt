package io.github.romantsisyk.cryptolib.certificates

/**
 * Data class representing the result of a certificate validation operation.
 *
 * @property isValid Whether the certificate or certificate chain is valid.
 * @property errors List of error messages encountered during validation.
 * @property warnings List of warning messages encountered during validation.
 */
data class ValidationResult(
    val isValid: Boolean,
    val errors: List<String> = emptyList(),
    val warnings: List<String> = emptyList()
) {
    companion object {
        /**
         * Creates a successful validation result.
         *
         * @param warnings Optional list of warnings (empty by default).
         * @return A ValidationResult indicating success.
         */
        fun success(warnings: List<String> = emptyList()): ValidationResult {
            return ValidationResult(isValid = true, warnings = warnings)
        }

        /**
         * Creates a failed validation result.
         *
         * @param errors List of error messages.
         * @param warnings Optional list of warnings (empty by default).
         * @return A ValidationResult indicating failure.
         */
        fun failure(errors: List<String>, warnings: List<String> = emptyList()): ValidationResult {
            return ValidationResult(isValid = false, errors = errors, warnings = warnings)
        }
    }
}
