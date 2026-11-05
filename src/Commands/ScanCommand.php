<?php

declare(strict_types=1);

namespace PhpShield\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use PhpShield\Scanner\Scanner;
use PhpShield\Hardener\Hardener;
use PhpShield\Reporters\ConsoleReporter;
use PhpShield\Issue;

/**
 * Console command that orchestrates scanning, optional auto-hardening,
 * and reporting of security issues.
 *
 * Supports --fix for automatic remediation, multiple output formats,
 * and project-specific configuration.
 */
final class ScanCommand extends Command
{
    protected static $defaultName = 'scan';
    protected static $defaultDescription = 'Scan PHP source for OWASP vulnerabilities and optionally auto-fix them.';

    protected function configure(): void
    {
        $this
            ->setName('scan')
            ->setDescription(self::$defaultDescription)
            ->setHelp(<<<HELP
The <info>scan</info> command recursively scans PHP files for common
security issues using AST analysis.

  <info>php-shield scan ./src</info>
  <info>php-shield scan ./src --fix</info>
  <info>php-shield scan ./src --format=html --report=report.html</info>
HELP)
            ->addArgument(
                'path',
                InputArgument::OPTIONAL,
                'Directory or file to scan',
                getcwd()
            )
            ->addOption(
                'fix',
                'f',
                InputOption::VALUE_NONE,
                'Automatically apply safe fixes where possible'
            )
            ->addOption(
                'format',
                null,
                InputOption::VALUE_REQUIRED,
                'Output format (console|html)',
                'console'
            )
            ->addOption(
                'config',
                'c',
                InputOption::VALUE_REQUIRED,
                'Path to configuration file',
                'shield.config.php'
            )
            ->addOption(
                'report',
                'r',
                InputOption::VALUE_REQUIRED,
                'Path for HTML report (when using --format=html)',
                'security-report.html'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        /** @var string $path */
        $path = $input->getArgument('path');
        $shouldFix = (bool) $input->getOption('fix');
        /** @var string $format */
        $format = $input->getOption('format');
        /** @var string $configPath */
        $configPath = $input->getOption('config');
        /** @var string $reportPath */
        $reportPath = $input->getOption('report');

        if (!in_array($format, ['console', 'html'], true)) {
            $io->error('Invalid format. Allowed values: console, html');
            return Command::INVALID;
        }

        if (!file_exists($path)) {
            $io->error(sprintf('Path "%s" does not exist.', $path));
            return Command::INVALID;
        }

        $config = $this->loadConfiguration($configPath, $io);

        $io->title('PHP Shield Security Scanner');
        $io->text(sprintf('Scanning <info>%s</info>...', realpath($path)));
        $io->newLine();

        $scanner = new Scanner($config);
        $issues = $scanner->scan($path);

        if ($issues === []) {
            $io->success('No vulnerabilities found. Your code looks secure!');
            return Command::SUCCESS;
        }

        if ($format === 'console') {
            $reporter = new ConsoleReporter($io);
            $reporter->render($issues, ['showFixSuggestions' => true]);
        } else {
            $this->generateHtmlReport($issues, $reportPath);
            $io->success(sprintf('HTML report written to <info>%s</info>', $reportPath));
        }

        if ($shouldFix) {
            $io->section('Applying automatic fixes');
            $hardener = new Hardener();
            $fixedCount = $hardener->harden($issues);
            $io->success(sprintf(
                'Applied <info>%d</info> automatic fix(es). %d issue(s) may require manual review.',
                $fixedCount,
                count($issues) - $fixedCount
            ));
        }

        $exitCode = count($issues) > 0 ? 1 : 0;
        $io->newLine();
        if ($exitCode !== 0) {
            $io->warning('Issues were found. Review the report above.');
        }

        return $exitCode;
    }

    /**
     * Loads configuration or falls back to sensible defaults.
     *
     * @return array<string, mixed>
     */
    private function loadConfiguration(string $configPath, SymfonyStyle $io): array
    {
        if (file_exists($configPath)) {
            $config = require $configPath;

            if (!is_array($config)) {
                $io->warning('Configuration file must return an array. Using defaults.');
                return $this->getDefaultConfig();
            }

            return array_merge($this->getDefaultConfig(), $config);
        }

        $io->comment('No configuration file found, using defaults.');
        return $this->getDefaultConfig();
    }

    /**
     * @return array<string, mixed>
     */
    private function getDefaultConfig(): array
    {
        return [
            'detectors' => [
                'sql-injection' => true,
                'xss' => true,
                'command-injection' => true,
                'unsafe-deserialization' => true,
                'unsafe-include' => true,
            ],
            'severity' => [
                'sql-injection' => 'critical',
                'xss' => 'high',
                'command-injection' => 'critical',
                'unsafe-deserialization' => 'high',
            ],
            'min-severity' => 'medium',
        ];
    }

    /**
     * Generates a self-contained HTML report with syntax-friendly styling.
     *
     * @param array<Issue> $issues
     */
    private function generateHtmlReport(array $issues, string $reportPath): void
    {
        $date = date('Y-m-d H:i:s');
        $count = count($issues);

        $rows = '';
        foreach ($issues as $issue) {
            $severity = $issue->getSeverity();
            $severityClass = strtolower($severity);
            $location = htmlspecialchars($issue->getFile() . ':' . $issue->getLine());
            $message = htmlspecialchars($issue->getMessage());
            $owasp = htmlspecialchars($issue->getOwaspCategory());
            $suggestion = htmlspecialchars($issue->getFixSuggestion());

            $rows .= <<<HTML
            <tr>
                <td class="severity {$severityClass}"><strong>{$severity}</strong></td>
                <td><code>{$location}</code></td>
                <td>{$message}</td>
                <td>{$owasp}</td>
                <td><pre>{$suggestion}</pre></td>
            </tr>

HTML;
        }

        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Shield Report — {$count} issue(s)</title>
    <style>
        :root {
            --bg: #f8f9fa;
            --text: #212529;
            --primary: #0d6efd;
            --border: #dee2e6;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #212529;
                --text: #f8f9fa;
                --primary: #0d6efd;
                --border: #495057;
            }
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }
        .header {
            background: var(--primary);
            color: white;
            padding: 2rem;
            border-radius: 8px 8px 0 0;
            margin-bottom: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        @media (prefers-color-scheme: dark) {
            .container {
                background: #343a40;
            }
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 14px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: #f1f3f5;
            font-weight: 600;
            color: #495057;
        }
        @media (prefers-color-scheme: dark) {
            th {
                background: #2b3035;
                color: #adb5bd;
            }
        }
        tr:hover {
            background: #f8f9fa;
        }
        @media (prefers-color-scheme: dark) {
            tr:hover {
                background: #3a3f45;
            }
        }
        .severity {
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8rem;
        }
        .critical { color: #c82333; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #6c757d; }
        pre {
            background: #f1f3f5;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            white-space: pre-wrap;
            margin: 0;
            max-height: 120px;
            overflow-y: auto;
        }
        @media (prefers-color-scheme: dark) {
            pre {
                background: #2b3035;
            }
        }
        .meta {
            padding: 1rem 2rem;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.9rem;
        }
        @media (prefers-color-scheme: dark) {
            .meta {
                background: #2b3035;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PHP Shield Security Report</h1>
            <p><strong>{$count}</strong> issue(s) found • Generated {$date}</p>
        </div>
        <div class="meta">
            Run with <code>--fix</code> to automatically harden vulnerable code.
        </div>
        <table>
            <thead>
                <tr>
                    <th width="80">Severity</th>
                    <th width="160">Location</th>
                    <th>Issue</th>
                    <th width="110">OWASP</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
{$rows}
            </tbody>
        </table>
    </div>
</body>
</html>
HTML;

        if (file_put_contents($reportPath, $html) === false) {
            throw new \RuntimeException(sprintf('Failed to write report to "%s"', $reportPath));
        }
    }
}
