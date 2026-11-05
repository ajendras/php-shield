<?php

declare(strict_types=1);

namespace PhpShield\Scanner;

use PhpParser\Error as ParserError;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use Symfony\Component\Finder\Finder;
use PhpShield\Context;
use PhpShield\Detectors\DetectorInterface;
use PhpShield\Detectors\SqlInjectionDetector;
use PhpShield\Issue;

/**
 * Orchestrates file discovery, AST parsing and running all detectors.
 *
 * Uses Symfony Finder for efficient file enumeration and nikic/php-parser
 * for robust AST-based analysis. Issues are aggregated across the entire project.
 */
final class Scanner
{
    /** @var list<DetectorInterface> */
    private array $detectors = [];

    /** @var array<string, mixed> */
    private array $config;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->registerEnabledDetectors();
    }

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
            'min-severity' => 'medium',
        ];
    }

    private function registerEnabledDetectors(): void
    {
        $detectorMap = [
            'sql-injection' => SqlInjectionDetector::class,
            // Additional detectors will be registered here as they are implemented.
            // 'xss' => \PhpShield\Detectors\XssDetector::class,
        ];

        foreach ($this->config['detectors'] as $name => $enabled) {
            if ($enabled && isset($detectorMap[$name])) {
                $this->detectors[] = new $detectorMap[$name]();
            }
        }
    }

    /**
     * Recursively scan the given path and return all detected issues.
     *
     * @param string $path Directory or single PHP file
     * @return list<Issue>
     */
    public function scan(string $path): array
    {
        if (!file_exists($path)) {
            throw new \InvalidArgumentException(sprintf('Path "%s" does not exist.', $path));
        }

        $issues = [];
        $finder = $this->createFinder($path);
        $parser = (new ParserFactory())->createForNewestSupportedVersion();

        foreach ($finder as $fileInfo) {
            $filePath = (string) $fileInfo->getRealPath();

            try {
                $code = file_get_contents($filePath);
                if ($code === false || trim($code) === '') {
                    continue;
                }

                $ast = $parser->parse($code);
                if ($ast === null) {
                    continue;
                }

                $fileIssues = $this->analyzeFile($ast, $filePath);
                $issues = [...$issues, ...$fileIssues];
            } catch (ParserError $e) {
                // Silently skip files that cannot be parsed (e.g. syntax errors)
                continue;
            }
        }

        // Filter by minimum severity
        $issues = array_filter($issues, fn(Issue $issue): bool => $this->meetsSeverityThreshold($issue));

        // Sort for consistent output
        usort($issues, static function (Issue $a, Issue $b): int {
            return [$a->getFile(), $a->getLine()] <=> [$b->getFile(), $b->getLine()];
        });

        return array_values($issues);
    }

    private function createFinder(string $path): Finder
    {
        $finder = new Finder();
        $finder
            ->files()
            ->name('*.php')
            ->exclude(['vendor', 'node_modules', 'tests', '.git'])
            ->ignoreVCS(true);

        if (is_dir($path)) {
            $finder->in($path);
        } elseif (is_file($path)) {
            $finder->in(dirname($path));
            $finder->name(basename($path));
        }

        return $finder;
    }

    /**
     * Run all detectors against every node in the AST of a single file.
     *
     * @return list<Issue>
     */
    private function analyzeFile(array $ast, string $filePath): array
    {
        $fileIssues = [];
        $context = new Context($filePath);

        $traverser = new NodeTraverser();
        $visitor = new class($this->detectors, $context, $fileIssues) extends NodeVisitorAbstract {
            /** @var list<DetectorInterface> */
            private array $detectors;

            private Context $context;

            /** @var list<Issue> */
            private array &$issues;

            /**
             * @param list<DetectorInterface> $detectors
             * @param list<Issue> $issues
             */
            public function __construct(array $detectors, Context $context, array &$issues)
            {
                $this->detectors = $detectors;
                $this->context = $context;
                $this->issues = &$issues;
            }

            public function enterNode(Node $node): ?Node
            {
                foreach ($this->detectors as $detector) {
                    $detected = $detector->detect($node, $this->context);
                    foreach ($detected as $issue) {
                        $this->issues[] = $issue;
                    }
                }

                return null;
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $fileIssues;
    }

    private function meetsSeverityThreshold(Issue $issue): bool
    {
        $minSeverity = $this->config['min-severity'] ?? 'medium';
        $scores = [
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
        ];

        $issueScore = $scores[strtolower($issue->getSeverity())] ?? 0;
        $minScore = $scores[strtolower($minSeverity)] ?? 2;

        return $issueScore >= $minScore;
    }
}
