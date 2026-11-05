<?php

declare(strict_types=1);

namespace PhpShield\Tests\Detectors;

use PHPUnit\Framework\TestCase;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpShield\Context;
use PhpShield\Detectors\SqlInjectionDetector;
use PhpShield\Issue;

/**
 * @covers \PhpShield\Detectors\SqlInjectionDetector
 */
final class SqlInjectionDetectorTest extends TestCase
{
    private SqlInjectionDetector $detector;
    private \PhpParser\Parser $parser;

    protected function setUp(): void
    {
        $this->detector = new SqlInjectionDetector();
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    /**
     * @dataProvider provideVulnerableSnippets
     */
    public function testDetectsVulnerablePatterns(string $snippet, string $expectedMessageContains): void
    {
        $issues = $this->analyzeSnippet($snippet, '/app/test.php');

        $this->assertCount(1, $issues, 'Exactly one issue should be reported');
        $issue = $issues[0];

        $this->assertInstanceOf(Issue::class, $issue);
        $this->assertSame('critical', $issue->getSeverity());
        $this->assertSame('A03:2021 - Injection', $issue->getOwaspCategory());
        $this->assertStringContainsString($expectedMessageContains, strtolower($issue->getMessage()));
        $this->assertStringContainsString('prepared statements', strtolower($issue->getFixSuggestion()));
    }

    /**
     * @dataProvider provideSafeSnippets
     */
    public function testIgnoresSafePatterns(string $snippet): void
    {
        $issues = $this->analyzeSnippet($snippet, '/app/test.php');
        $this->assertCount(0, $issues, 'No issues should be reported for safe code');
    }

    public function testHandlesEmptyAndInvalidCodeGracefully(): void
    {
        $issues = $this->analyzeSnippet('<?php', '/app/empty.php');
        $this->assertCount(0, $issues);

        // Malformed code is skipped by the scanner, but we test that detector itself
        // does not throw when given partial nodes.
        $issues = $this->analyzeSnippet('<?php echo "no sql";', '/app/invalid.php');
        $this->assertCount(0, $issues);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function provideVulnerableSnippets(): array
    {
        return [
            'concatenated_user_input' => [
                <<<'PHP'
<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$pdo->query($sql);
PHP,
                'unsanitized user input',
            ],
            'encapsed_interpolation' => [
                <<<'PHP'
<?php
$name = $_POST['name'];
$sql = "SELECT name FROM users WHERE name = '$name'";
$result = mysqli_query($conn, $sql);
PHP,
                'unsanitized',
            ],
            'legacy_mysql_query' => [
                <<<'PHP'
<?php
mysql_query("DELETE FROM users WHERE id = " . $_GET['id']);
PHP,
                'unsafe database query',
            ],
            'pdo_exec_with_variable' => [
                <<<'PHP'
<?php
$userInput = $_GET['q'];
$pdo->exec("UPDATE logs SET data = " . $userInput);
PHP,
                'unsafe database query',
            ],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideSafeSnippets(): array
    {
        return [
            'prepared_statement_pdo' => [
                <<<'PHP'
<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
PHP,
            ],
            'prepared_statement_mysqli' => [
                <<<'PHP'
<?php
$stmt = $mysqli->prepare("SELECT * FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
PHP,
            ],
            'static_query_no_variables' => [
                <<<'PHP'
<?php
$pdo->query("SELECT * FROM settings WHERE id = 1");
PHP,
            ],
            'string_without_sql_keywords' => [
                <<<'PHP'
<?php
echo "Hello " . $name;
PHP,
            ],
            'htmlspecialchars_in_output' => [
                <<<'PHP'
<?php
echo htmlspecialchars($userInput);
PHP,
            ],
            'concatenation_in_non_sql_context' => [
                <<<'PHP'
<?php
$greeting = "Hello, " . $name;
echo $greeting;
PHP,
            ],
        ];
    }

    /**
     * Runs the detector against every node in a snippet.
     *
     * @return list<Issue>
     */
    private function analyzeSnippet(string $snippet, string $filePath): array
    {
        $ast = $this->parser->parse($snippet);
        $this->assertNotNull($ast, 'Parser should return AST for test snippet');

        $issues = [];
        $context = new Context($filePath);

        $traverser = new NodeTraverser();
        $visitor = new class($this->detector, $context, $issues) extends \PhpParser\NodeVisitorAbstract {
            private SqlInjectionDetector $detector;
            private Context $context;
            /** @var list<Issue> */
            private array &$issues;

            public function __construct(SqlInjectionDetector $detector, Context $context, array &$issues)
            {
                $this->detector = $detector;
                $this->context = $context;
                $this->issues = &$issues;
            }

            public function enterNode(\PhpParser\Node $node): void
            {
                $detected = $this->detector->detect($node, $this->context);
                foreach ($detected as $issue) {
                    $this->issues[] = $issue;
                }
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $issues;
    }
}
