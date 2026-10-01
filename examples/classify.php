<?php

declare(strict_types=1);

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException as PsrInvalidArgumentException;
use VerifiedBots\AutomaticBotVerifier;

require dirname(__DIR__).'/vendor/autoload.php';

final class ExampleInvalidCacheKey extends InvalidArgumentException implements PsrInvalidArgumentException
{
}

/**
 * Minimal persistent PSR-16 cache for this command-line example.
 *
 * A persistent cache matters because xargs starts a new PHP process for every
 * log line. Applications should normally inject their existing PSR-16 cache.
 */
final class ExampleFileCache implements CacheInterface
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory)
            && !mkdir($directory, 0700, true)
            && !is_dir($directory)
        ) {
            throw new RuntimeException('Cannot create cache directory: '.$directory);
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $path = $this->path($key);
        $handle = @fopen($path, 'rb');

        if ($handle === false) {
            return $default;
        }

        if (!flock($handle, LOCK_SH)) {
            fclose($handle);

            return $default;
        }

        $json = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        if (!is_string($json) || $json === '') {
            return $default;
        }

        try {
            $record = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $default;
        }

        if (!is_array($record)
            || !array_key_exists('value', $record)
            || !array_key_exists('expiresAt', $record)
            || (!is_int($record['expiresAt']) && $record['expiresAt'] !== null)
        ) {
            return $default;
        }

        if ($record['expiresAt'] !== null && $record['expiresAt'] <= time()) {
            @unlink($path);

            return $default;
        }

        return $record['value'];
    }

    public function set(
        string $key,
        mixed $value,
        null|int|DateInterval $ttl = null,
    ): bool {
        if (is_int($ttl) && $ttl <= 0) {
            return $this->delete($key);
        }

        $expiresAt = match (true) {
            is_int($ttl) => time() + $ttl,
            $ttl instanceof DateInterval => (new DateTimeImmutable())->add($ttl)->getTimestamp(),
            default => null,
        };

        try {
            $json = json_encode(
                ['expiresAt' => $expiresAt, 'value' => $value],
                JSON_THROW_ON_ERROR,
            );
        } catch (JsonException) {
            return false;
        }

        $handle = @fopen($this->path($key), 'c+b');

        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) {
                fclose($handle);
            }

            return false;
        }

        $success = ftruncate($handle, 0)
            && rewind($handle)
            && fwrite($handle, $json) === strlen($json)
            && fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return $success;
    }

    public function delete(string $key): bool
    {
        $path = $this->path($key);

        return !is_file($path) || @unlink($path);
    }

    public function clear(): bool
    {
        $paths = glob($this->directory.DIRECTORY_SEPARATOR.'*.json');

        if ($paths === false) {
            return false;
        }

        $success = true;

        foreach ($paths as $path) {
            $success = @unlink($path) && $success;
        }

        return $success;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->get((string) $key, $default);
        }
    }

    public function setMultiple(
        iterable $values,
        null|int|DateInterval $ttl = null,
    ): bool {
        $success = true;

        foreach ($values as $key => $value) {
            $success = $this->set((string) $key, $value, $ttl) && $success;
        }

        return $success;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $success = true;

        foreach ($keys as $key) {
            $success = $this->delete((string) $key) && $success;
        }

        return $success;
    }

    public function has(string $key): bool
    {
        $missing = new stdClass();

        return $this->get($key, $missing) !== $missing;
    }

    private function path(string $key): string
    {
        if ($key === '' || preg_match('/[{}()\/\\\\@:]/', $key) === 1) {
            throw new ExampleInvalidCacheKey('Invalid cache key.');
        }

        return $this->directory.DIRECTORY_SEPARATOR.hash('sha256', $key).'.json';
    }
}

$cacheDirectory = getenv('VERIFIED_BOTS_CACHE_DIR');
$cacheDirectory = is_string($cacheDirectory) && $cacheDirectory !== ''
    ? $cacheDirectory
    : sys_get_temp_dir().DIRECTORY_SEPARATOR.'verified-bots-cache';

try {
    $verifier = new AutomaticBotVerifier(
        new ExampleFileCache($cacheDirectory),
        enableWebBotAuth: false,
    );
} catch (Throwable $exception) {
    fwrite(STDERR, "Cannot initialize verifier: ".$exception->getMessage().PHP_EOL);
    exit(1);
}

$classify = static function (
    string $line,
    int $lineNumber,
) use ($verifier): bool {
    $line = rtrim($line, "\r\n");

    if ($line === '') {
        return true;
    }

    if (!str_contains($line, "\t")) {
        fwrite(STDERR, sprintf(
            "Line %d: expected IP, tab, and User-Agent.\n",
            $lineNumber,
        ));

        return false;
    }

    [$ipAddress, $userAgent] = explode("\t", $line, 2);
    $ipAddress = trim($ipAddress);

    try {
        $status = $verifier->classify($ipAddress, $userAgent);
        fwrite(STDOUT, $ipAddress."\t".$status->value."\t".$userAgent.PHP_EOL);

        return true;
    } catch (Throwable $exception) {
        fwrite(STDERR, sprintf(
            "Line %d (%s): %s\n",
            $lineNumber,
            $ipAddress,
            $exception->getMessage(),
        ));

        return false;
    }
};

$success = true;

if (($argc ?? 0) === 2) {
    $success = $classify($argv[1], 1);
} elseif (($argc ?? 0) === 1) {
    $lineNumber = 0;

    while (($line = fgets(STDIN)) !== false) {
        $success = $classify($line, ++$lineNumber) && $success;
    }
} else {
    $usage = <<<'USAGE'
Usage:
  sed -nE 's/^([^ ]+) .*"[^"]*" [0-9]{3} [0-9-]+ "[^"]*" "([^"]*)".*$/\1\t\2/p' access.log | php examples/classify.php
  php examples/classify.php $'IP\tUser-Agent'
USAGE;
    fwrite(STDERR, $usage.PHP_EOL);
    exit(64);
}

exit($success ? 0 : 1);
