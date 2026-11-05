<?php

declare(strict_types=1);

namespace PhpShield\Reporters;

use PhpShield\Issue;

/**
 * Contract for all output formatters/reporters.
 *
 * Concrete implementations (ConsoleReporter, HtmlReporter, etc.)
 * receive the aggregated issues and render them according to
 * user-selected options (--format, --report, etc).
 */
interface ReporterInterface
{
    /**
     * Render the list of detected issues.
     *
     * @param list<Issue> $issues
     * @param array<string, mixed> $options Behavioral flags (e.g. showFixSuggestions, reportPath)
     */
    public function render(array $issues, array $options = []): void;
}
