<?php

declare(strict_types=1);

namespace PhpShield\Detectors;

use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Stmt\Echo_;
use PhpShield\Context;
use PhpShield\Issue;

/**
 * Detects Cross-Site Scripting (XSS) vulnerabilities.
 *
 * Identifies echo, print, printf and similar constructs that output
 * unsanitized variables or dynamic expressions without calling
 * htmlspecialchars(), htmlentities() or equivalent escaping functions.
 */
final class XssDetector implements DetectorInterface
{
    private const SEVERITY = 'high';
    private const OWASP_CATEGORY = 'A03:2021 - Injection';

    /**
     * {@inheritdoc}
     */
    public function detect(Node $node, Context $ctx): array
    {
        if (!$this->isPotentialXssOutput($node)) {
            return [];
        }

        return [
            new Issue(
                self::SEVERITY,
                $ctx->getFile(),
                (int) $node->getStartLine(),
                'Unsanitized variable is being output directly. This can lead to cross-site scripting (XSS).',
                self::OWASP_CATEGORY,
                'Use htmlspecialchars() or a secure templating system: echo htmlspecialchars($userInput, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');'
            ),
        ];
    }

    private function isPotentialXssOutput(Node $node): bool
    {
        // echo statements (including <?= ?> short tags)
        if ($node instanceof Echo_) {
            foreach ($node->exprs as $expr) {
                if ($this->isUnsanitizedDynamic($expr)) {
                    return true;
                }
            }
        }

        // print construct
        if ($node instanceof Print_ && $this->isUnsanitizedDynamic($node->expr)) {
            return true;
        }

        // printf, vprintf, fprintf, and direct echo/print function calls
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            $name = strtolower($node->name->toString());
            if (in_array($name, ['echo', 'print', 'printf', 'vprintf', 'fprintf'], true)) {
                foreach ($node->args as $arg) {
                    $value = $arg->value;
                    if ($this->isUnsanitizedDynamic($value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function isUnsanitizedDynamic(Node $node): bool
    {
        if ($this->isEscapingCall($node)) {
            return false;
        }

        return $node instanceof Variable
            || $node instanceof Concat
            || $node instanceof Encapsed
            || $node instanceof FuncCall;
    }

    private function isEscapingCall(Node $node): bool
    {
        if (!$node instanceof FuncCall || !$node->name instanceof Name) {
            return false;
        }

        $func = strtolower($node->name->toString());

        return in_array($func, ['htmlspecialchars', 'htmlentities'], true)
            || str_contains($func, 'escape');
    }
}
