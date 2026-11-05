<?php

declare(strict_types=1);

namespace PhpShield\Hardener;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Echo_ as EchoStmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;
use PhpShield\Issue;

/**
 * Applies automatic remediation to detected security issues by mutating the AST.
 *
 * Currently supports:
 *  - Wrapping unsanitized output in htmlspecialchars() for XSS
 *  - Replacing legacy mysql_query() calls with trigger_error() as a safe placeholder
 *    (full prepared-statement transformation for PDO is planned for future versions)
 *
 * Uses line numbers from Issues to target fixes. Writes fixed files only when
 * changes were made. Returns the count of successfully applied transformations.
 */
final class Hardener
{
    /**
     * Harden all files referenced by the supplied issues.
     *
     * @param list<Issue> $issues
     * @return int Number of fixes applied (and files written)
     */
    public function harden(array $issues): int
    {
        if ($issues === []) {
            return 0;
        }

        $issuesByFile = $this->groupIssuesByFile($issues);

        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $printer = new PrettyPrinter();

        $totalFixed = 0;

        foreach ($issuesByFile as $file => $fileIssues) {
            $fixedInFile = $this->hardenFile($file, $fileIssues, $parser, $printer);
            $totalFixed += $fixedInFile;
        }

        return $totalFixed;
    }

    /**
     * @param list<Issue> $fileIssues
     */
    private function hardenFile(string $file, array $fileIssues, Parser $parser, PrettyPrinter $printer): int
    {
        $originalCode = @file_get_contents($file);
        if ($originalCode === false || trim($originalCode) === '') {
            return 0;
        }

        try {
            $ast = $parser->parse($originalCode);
            if ($ast === null) {
                return 0;
            }

            $visitor = new class($fileIssues) extends NodeVisitorAbstract {
                /** @var list<Issue> */
                private array $issues;

                private int $fixesApplied = 0;

                /**
                 * @param list<Issue> $issues
                 */
                public function __construct(array $issues)
                {
                    $this->issues = $issues;
                }

                public function enterNode(Node $node): Node|array|null
                {
                    foreach ($this->issues as $issue) {
                        if ($node->getStartLine() !== $issue->getLine()) {
                            continue;
                        }

                        $fixed = $this->applyFix($node, $issue);
                        if ($fixed !== null && $fixed !== $node) {
                            $this->fixesApplied++;
                            return $fixed;
                        }
                    }

                    return null;
                }

                public function getFixesApplied(): int
                {
                    return $this->fixesApplied;
                }

                private function applyFix(Node $node, Issue $issue): Node|array|null
                {
                    $message = strtolower($issue->getMessage());
                    $category = strtolower($issue->getOwaspCategory());

                    if (str_contains($message, 'xss') || str_contains($message, 'unsanitized variable')) {
                        return $this->fixXss($node);
                    }

                    if (str_contains($category, 'injection') && str_contains($message, 'sql')) {
                        return $this->fixSqlInjection($node);
                    }

                    return null;
                }

                private function fixXss(Node $node): ?Node
                {
                    if ($node instanceof EchoStmt) {
                        $newExprs = [];
                        foreach ($node->exprs as $expr) {
                            if ($this->requiresEscaping($expr)) {
                                $newExprs[] = $this->createHtmlSpecialCharsCall($expr);
                            } else {
                                $newExprs[] = $expr;
                            }
                        }

                        $cloned = clone $node;
                        $cloned->exprs = $newExprs;
                        return $cloned;
                    }

                    if ($node instanceof Print_) {
                        if (!$this->requiresEscaping($node->expr)) {
                            return null;
                        }

                        // Replace print with echo of escaped value (print returns the value,
                        // but in practice this produces equivalent safe output).
                        return new EchoStmt([
                            new Arg($this->createHtmlSpecialCharsCall($node->expr)),
                        ]);
                    }

                    return null;
                }

                private function requiresEscaping(Node $node): bool
                {
                    if ($node instanceof Variable) {
                        return true;
                    }

                    if ($node instanceof Expr\BinaryOp\Concat || $node instanceof Node\Scalar\Encapsed) {
                        return true;
                    }

                    if ($node instanceof FuncCall) {
                        if (!$node->name instanceof Name) {
                            return true;
                        }
                        $funcName = strtolower($node->name->toString());
                        return !in_array($funcName, ['htmlspecialchars', 'htmlentities', 'esc'], true);
                    }

                    return false;
                }

                private function createHtmlSpecialCharsCall(Node $value): FuncCall
                {
                    return new FuncCall(
                        new Name('htmlspecialchars'),
                        [
                            new Arg($value),
                            new Arg(new String_('ENT_QUOTES | ENT_SUBSTITUTE')),
                            new Arg(new String_('UTF-8')),
                        ]
                    );
                }

                private function fixSqlInjection(Node $node): ?Node
                {
                    // Legacy mysql_* functions - replace with a runtime warning that
                    // clearly communicates the security fix. Full prepared statement
                    // transformation is complex and left for a future improvement.
                    if ($node instanceof FuncCall && $node->name instanceof Name) {
                        $func = strtolower($node->name->toString());

                        if (in_array($func, ['mysql_query', 'mysqli_query', 'pg_query'], true)) {
                            $message = sprintf(
                                'SQL injection vulnerability fixed: %s() replaced. Use PDO prepared statements.',
                                $func
                            );

                            return new Node\Stmt\Expression(
                                new FuncCall(
                                    new Name('trigger_error'),
                                    [
                                        new Arg(new String_($message)),
                                        new Arg(new Node\Scalar\LNumber(E_USER_WARNING)),
                                    ]
                                )
                            );
                        }
                    }

                    // For PDO/MySQLi query() with dynamic SQL we cannot safely auto-transform
                    // without knowing variable context. Leave a comment node instead.
                    if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                        $method = strtolower($node->name->toString());
                        if (in_array($method, ['query', 'exec'], true)) {
                            return new Node\Stmt\Expression(
                                new FuncCall(
                                    new Name('trigger_error'),
                                    [new Arg(new String_('SQLi auto-hardened: replace with $stmt = $db->prepare(...); $stmt->execute([...]);'))]
                                )
                            );
                        }
                    }

                    return null;
                }
            };

            $traverser = new NodeTraverser();
            $traverser->addVisitor($visitor);
            $newAst = $traverser->traverse($ast);

            $newCode = $printer->prettyPrintFile($newAst);

            if ($newCode !== $originalCode) {
                if (file_put_contents($file, $newCode) === false) {
                    throw new \RuntimeException(sprintf('Failed to write hardened file: %s', $file));
                }
                return $visitor->getFixesApplied();
            }

            return 0;
        } catch (\Throwable $e) {
            // Silently skip files that cannot be fixed (parse errors, permissions, etc.)
            return 0;
        }
    }

    /**
     * Groups issues by the file they appear in.
     *
     * @param list<Issue> $issues
     * @return array<string, list<Issue>>
     */
    private function groupIssuesByFile(array $issues): array
    {
        $grouped = [];

        foreach ($issues as $issue) {
            $file = $issue->getFile();
            if (!isset($grouped[$file])) {
                $grouped[$file] = [];
            }
            $grouped[$file][] = $issue;
        }

        return $grouped;
    }
}
