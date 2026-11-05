<?php

declare(strict_types=1);

namespace PhpShield;

/**
 * Immutable value object representing a single detected security issue.
 *
 * Contains severity, location, description, OWASP mapping and a concrete
 * remediation suggestion. Used by scanners, hardeners and all reporters.
 */
final class Issue
{
    /**
     * @param string $severity One of: critical, high, medium, low
     * @param string $file Absolute or relative path to the file
     * @param int $line Line number where the issue was detected
     * @param string $message Human-readable description of the vulnerability
     * @param string $owaspCategory OWASP Top 10 mapping (e.g. "A03:2021 - Injection")
     * @param string $fixSuggestion Concrete suggestion for remediation
     */
    public function __construct(
        private readonly string $severity,
        private readonly string $file,
        private readonly int $line,
        private readonly string $message,
        private readonly string $owaspCategory,
        private readonly string $fixSuggestion,
    ) {
        $valid = ['critical', 'high', 'medium', 'low'];
        $normalized = strtolower($severity);

        if (!in_array($normalized, $valid, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid severity "%s". Must be one of: %s.',
                $severity,
                implode(', ', $valid)
            ));
        }
    }

    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function getFile(): string
    {
        return $this->file;
    }

    public function getLine(): int
    {
        return $this->line;
    }

    public function getMessage(): string
    {
        return $this->message;
    }

    public function getOwaspCategory(): string
    {
        return $this->owaspCategory;
    }

    public function getFixSuggestion(): string
    {
        return $this->fixSuggestion;
    }

    /**
     * Returns a compact array representation useful for reporters.
     *
     * @return array{
     *   severity: string,
     *   file: string,
     *   line: int,
     *   message: string,
     *   owaspCategory: string,
     *   fixSuggestion: string
     * }
     */
    public function toArray(): array
    {
        return [
            'severity' => $this->severity,
            'file' => $this->file,
            'line' => $this->line,
            'message' => $this->message,
            'owaspCategory' => $this->owaspCategory,
            'fixSuggestion' => $this->fixSuggestion,
        ];
    }
}
