# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-05

### Added

- AST-Powered Scanner — Uses nikic/php-parser for precise, context-aware detection across 25 vulnerability patterns
- OWASP Coverage — Built-in detectors for SQLi, XSS, command injection, unsafe deserialization and more
- Auto Hardener — Rewrites vulnerable code into secure equivalents using prepared statements and escaping
- Rich Reports — Beautiful terminal tables plus exportable HTML reports with syntax highlighting
- Severity & Mapping — Scores each issue and maps it to current OWASP Top 10 with remediation guidance
- Configurable Rules — Simple PHP config file to enable/disable detectors or tune severity per project
- Lightning Fast — Scans thousands of files in seconds with zero runtime overhead
- Tested Detectors — Comprehensive PHPUnit suite validates each detector against real-world snippets
