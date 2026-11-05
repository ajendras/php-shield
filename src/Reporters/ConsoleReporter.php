<?php

declare(strict_types=1);

namespace PhpShield\Reporters;

use PhpShield\Issue;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Renders security issues as a color-coded terminal table using SymfonyStyle.
 *
 * Displays severity with emojis and colors, file locations, messages,
 * OWASP categories, and optional fix suggestions. Provides a polished
 * developer-friendly output with summary statistics.
 */
final class ConsoleReporter implements ReporterInterface
{
    private SymfonyStyle $io;

    public function __construct(SymfonyStyle $io)
    {
        $this->io = $io;
    }

    /**
     * {@inheritdoc}
     */
    public function render(array $issues, array $options = []): void
    {
        if ($issues === []) {
            $this->io->success('No security issues detected.');
            return;
        }

        $showFixSuggestions = $options['showFixSuggestions'] ?? false;

        $rows = [];
        $severityCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($issues as $issue) {
            $severity = strtolower($issue->getSeverity());
            $severityCounts[$severity] = ($severityCounts[$severity] ?? 0) + 1;

            $emoji = $this->getSeverityEmoji($severity);
            $styledSeverity = match ($severity) {
                'critical' => "<fg=red>{$emoji} CRITICAL</>",
                'high' => "<fg=yellow>{$emoji} HIGH</>",
                'medium' => "<fg=blue>{$emoji} MEDIUM</>",
                'low' => "<fg=gray>{$emoji} LOW</>",
                default => $severity,
            };

            $location = sprintf(
                '%s:%d',
                str_replace(getcwd() ?: '', '.', $issue->getFile()),
                $issue->getLine()
            );

            $row = [
                $styledSeverity,
                $location,
                $this->wrapText($issue->getMessage(), 60),
                $issue->getOwaspCategory(),
            ];

            if ($showFixSuggestions) {
                $row[] = $this->wrapText($issue->getFixSuggestion(), 50);
            }

            $rows[] = $row;
        }

        $headers = ['Severity', 'Location', 'Issue', 'OWASP'];
        if ($showFixSuggestions) {
            $headers[] = 'Remediation';
        }

        $this->io->table($headers, $rows);

        $this->io->newLine();
        $this->printSummary($severityCounts, count($issues));
        $this->io->newLine();
    }

    private function getSeverityEmoji(string $severity): string
    {
        return match ($severity) {
            'critical' => '🔥',
            'high' => '🚨',
            'medium' => '⚠️',
            'low' => 'ℹ️',
            default => '•',
        };
    }

    private function wrapText(string $text, int $maxWidth): string
    {
        if (strlen($text) <= $maxWidth) {
            return $text;
        }

        return substr($text, 0, $maxWidth - 3) . '...';
    }

    /**
     * @param array<string, int> $counts
     */
    private function printSummary(array $counts, int $total): void
    {
        $critical = $counts['critical'] ?? 0;
        $high = $counts['high'] ?? 0;

        if ($critical > 0) {
            $this->io->error(sprintf(
                '%d critical and %d high severity issues found. Immediate action recommended.',
                $critical,
                $high
            ));
        } elseif ($high > 0) {
            $this->io->warning(sprintf('%d high severity issues found.', $high));
        } else {
            $this->io->note('All detected issues are medium or low severity.');
        }

        $this->io->text(sprintf(
            '<fg=gray>Total: <info>%d</info> issue(s) across <info>%d</info> severity level(s)</>',
            $total,
            count(array_filter($counts, fn(int $c): bool => $c > 0))
        ));
    }
}
