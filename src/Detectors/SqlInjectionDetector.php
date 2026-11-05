<?php

declare(strict_types=1);

namespace PhpShield\Detectors;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Scalar\EncapsedStringPart;
use PhpParser\Node\Scalar\String_;
use PhpShield\Context;
use PhpShield\Issue;

/**
 * Detects SQL Injection vulnerabilities.
 *
 * Looks for:
 *  - Variable concatenation or interpolation into SQL query strings
 *  - Direct use of query()/exec() with dynamic non-prepared arguments
 *  - Calls to legacy DB functions like mysql_query()
 */
final class SqlInjectionDetector implements DetectorInterface
{
    private const SEVERITY = 'critical';
    private const OWASP_CATEGORY = 'A03:2021 - Injection';

    /**
     * {@inheritdoc}
     */
    public function detect(Node $node, Context $ctx): array
    {
        $issues = [];

        if ($this->isUnsanitizedSqlConcatenation($node) || $this->isUnsanitizedSqlInterpolation($node)) {
            $issues[] = new Issue(
                self::SEVERITY,
                $ctx->getFile(),
                $node->getStartLine(),
                'SQL query constructed using unsanitized user input (concatenation/interpolation)',
                self::OWASP_CATEGORY,
                'Use prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);'
            );
        }

        if ($this->isUnsafeDatabaseCall($node)) {
            $issues[] = new Issue(
                self::SEVERITY,
                $ctx->getFile(),
                $node->getStartLine(),
                'Unsafe database query method called with dynamic SQL',
                self::OWASP_CATEGORY,
                'Switch to prepared statements and bound parameters instead of embedding variables directly.'
            );
        }

        return $issues;
    }

    private function isUnsanitizedSqlConcatenation(Node $node): bool
    {
        if (!$node instanceof Concat) {
            return false;
        }

        $parts = $this->flattenConcat($node);
        $hasSql = false;
        $hasDynamic = false;

        foreach ($parts as $part) {
            if ($part instanceof String_ && $this->looksLikeSql($part->value)) {
                $hasSql = true;
            } elseif ($part instanceof Variable || $part instanceof Expr) {
                $hasDynamic = true;
            }
        }

        return $hasSql && $hasDynamic;
    }

    private function isUnsanitizedSqlInterpolation(Node $node): bool
    {
        if (!$node instanceof Encapsed) {
            return false;
        }

        $content = '';
        $hasDynamic = false;

        foreach ($node->parts as $part) {
            if ($part instanceof EncapsedStringPart) {
                $content .= $part->value;
            } else {
                $hasDynamic = true;
            }
        }

        return $hasDynamic && $this->looksLikeSql($content);
    }

    /**
     * Recursively flatten a concatenation expression into its component parts.
     *
     * @return list<Node>
     */
    private function flattenConcat(Concat $concat): array
    {
        $parts = [];

        foreach ([$concat->left, $concat->right] as $side) {
            if ($side instanceof Concat) {
                $parts = array_merge($parts, $this->flattenConcat($side));
            } else {
                $parts[] = $side;
            }
        }

        return $parts;
    }

    private function looksLikeSql(string $str): bool
    {
        $upper = strtoupper(trim($str));
        $sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'HAVING', 'JOIN', 'LIMIT', 'ORDER BY'];

        foreach ($sqlKeywords as $keyword) {
            if (str_contains($upper, $keyword)) {
                return true;
            }
        }

        return false;
    }

    private function isUnsafeDatabaseCall(Node $node): bool
    {
        // Legacy functions
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            $funcName = strtolower($node->name->toString());
            if (in_array($funcName, ['mysql_query', 'mysqli_query', 'pg_query', 'sqlite_query'], true)) {
                if (isset($node->args[0]) && !$this->isLiteral($node->args[0]->value)) {
                    return true;
                }
            }
        }

        // PDO / MySQLi method calls
        if ($node instanceof MethodCall && $node->name instanceof Identifier) {
            $methodName = strtolower($node->name->toString());
            if (in_array($methodName, ['query', 'exec', 'execute'], true)) {
                if (isset($node->args[0]) && $this->isDynamicArgument($node->args[0]->value)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isLiteral(Node $node): bool
    {
        return $node instanceof String_ || $node instanceof Encapsed;
    }

    private function isDynamicArgument(Node $node): bool
    {
        return $node instanceof Variable
            || $node instanceof Concat
            || $node instanceof Encapsed;
    }
}
