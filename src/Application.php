<?php

declare(strict_types=1);

namespace PhpShield;

use Symfony\Component\Console\Application as BaseApplication;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;
use PhpShield\Commands\ScanCommand;
use Throwable;

/**
 * Main PHP Shield console application.
 *
 * Registers all commands, sets version information, and provides centralized
 * error handling for a polished CLI experience.
 */
final class Application extends BaseApplication
{
    private const VERSION = '0.1.0';

    public function __construct()
    {
        parent::__construct('PHP Shield', self::VERSION);

        $this->add(new ScanCommand());
        $this->setDefaultCommand('scan', true);
    }

    public function run(InputInterface $input = null, OutputInterface $output = null): int
    {
        $this->setupErrorHandling();

        if ($output === null) {
            $output = new ConsoleOutput();
        }

        try {
            return parent::run($input, $output);
        } catch (Throwable $e) {
            $this->renderThrowable($e, $output);
            return 1;
        }
    }

    private function setupErrorHandling(): void
    {
        set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
            if (!(error_reporting() & $severity)) {
                return false;
            }
            throw new \ErrorException($message, 0, $severity, $file, $line);
        });
    }

    private function renderThrowable(Throwable $exception, OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('<error>  PHP Shield Error  </error>');
        $output->writeln('');
        $output->writeln('<error>' . $exception->getMessage() . '</error>');
        $output->writeln('');
        $output->writeln('<fg=gray>Trace:</>');
        $output->writeln('<fg=gray>' . $exception->getTraceAsString() . '</>');
        $output->writeln('');
        $output->writeln('<comment>Run with -v for more details.</comment>');
    }
}
