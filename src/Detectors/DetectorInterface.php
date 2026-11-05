<?php

declare(strict_types=1);

namespace PhpShield\Detectors;

use PhpParser\Node;
use PhpShield\Context;
use PhpShield\Issue;

/**
 * Contract that every vulnerability detector must fulfill.
 *
 * Each detector is invoked for every node in the AST. This design allows
 * detectors to focus on specific patterns without managing traversal themselves.
 */
interface DetectorInterface
{
    /**
     * Detect issues in the provided node.
     *
     * @param Node $node Current AST node
     * @param Context $ctx File and analysis context
     * @return list<Issue> Any issues detected (empty if none)
     */
    public function detect(Node $node, Context $ctx): array;
}
