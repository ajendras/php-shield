<?php

declare(strict_types=1);

/**
 * PHP Shield Vulnerable Demo
 *
 * This file contains deliberate security vulnerabilities for demonstration,
 * testing, and integration purposes. Running `php-shield scan examples/vulnerable.php`
 * (or with --fix) will detect and (where possible) remediate the issues.
 *
 * DO NOT use this code in production.
 */

echo "=== PHP Shield Vulnerable Example ===\n\n";

// ============================================================================
// 1. SQL Injection (A03:2021 - Injection)
// ============================================================================

// Vulnerable: direct concatenation of user input into SQL query
$userId = $_GET['id'] ?? 1;
$sql = "SELECT * FROM users WHERE id = " . $userId;
echo "Unsafe SQL (concatenation): " . $sql . "\n";

// Vulnerable: using query() with dynamic SQL instead of prepare()
$pdo = new PDO('sqlite::memory:'); // dummy connection for demo
$pdo->query("UPDATE users SET name = 'test' WHERE id = " . $_POST['id'] ?? '0');

// Vulnerable: legacy mysql_query with unsanitized input
$username = $_GET['username'] ?? '';
mysql_query("SELECT * FROM users WHERE username = '" . $username . "'"); // @phpstan-ignore-line

// ============================================================================
// 2. Cross-Site Scripting (XSS) (A03:2021 - Injection)
// ============================================================================

// Vulnerable: unsanitized output of user-controlled data
$name = $_GET['name'] ?? 'Guest';
echo "Welcome, " . $name . "!<br>"; // XSS possible

// Vulnerable: print with dynamic content
$comment = $_POST['comment'] ?? '';
print("<div class='comment'>{$comment}</div>");

// Vulnerable: echo of concatenated user input without escaping
$greeting = 'Hello, ';
echo $greeting . htmlspecialchars($_GET['user'] ?? ''); // only one is escaped

// ============================================================================
// 3. Unsafe Include / File Inclusion (A01:2021 - Broken Access Control)
// ============================================================================

// Vulnerable: including file based on user input (Local File Inclusion)
$template = $_GET['template'] ?? 'default';
include($template . '.php'); // could allow ../../etc/passwd

// ============================================================================
// 4. Command Injection (A03:2021 - Injection)
// ============================================================================

// Vulnerable: passing unsanitized input to shell command
$filename = $_GET['file'] ?? 'report.txt';
system("cat " . $filename); // @phpstan-ignore-line

// Vulnerable: exec with concatenated command
$userCommand = $_POST['cmd'] ?? 'ls';
exec('ls -l ' . escapeshellarg($userCommand)); // still unsafe in some contexts

// ============================================================================
// 5. Unsafe Deserialization (A08:2021 - Software and Data Integrity Failures)
// ============================================================================

// Vulnerable: unserialize() on user-controlled data
$serialized = $_GET['data'] ?? 'a:0:{}';
$data = unserialize($serialized); // can lead to object injection

// ============================================================================
// Safe equivalents (for contrast - these should NOT trigger detectors)
// ============================================================================

function safeExample(): void
{
    // Safe SQL with prepared statements
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_GET['id'] ?? 1]);

    // Safe output with escaping
    $name = $_GET['name'] ?? 'Guest';
    echo htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    // Safe include with whitelist
    $allowed = ['default', 'profile'];
    $template = $_GET['template'] ?? 'default';
    if (in_array($template, $allowed, true)) {
        include($template . '.php');
    }
}

// Run a safe example when this file is executed directly
if (php_sapi_name() === 'cli') {
    echo "\n\nThis file is for demonstration only.\n";
    echo "Run: php-shield scan examples/vulnerable.php --fix\n";
    echo "Then review the changes made by the Hardener.\n";
}
