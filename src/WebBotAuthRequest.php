<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;

final readonly class WebBotAuthRequest
{
    /** @var array<string, string> */
    private array $normalizedHeaders;

    /**
     * @param array<string, string|list<string>> $headers
     */
    public function __construct(
        public string $method,
        public string $targetUri,
        array $headers,
    ) {
        $parts = parse_url($targetUri);

        if (!is_array($parts)
            || !in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || !is_string($parts['host'] ?? null)
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
        ) {
            throw new InvalidArgumentException('The request target must be an absolute HTTP(S) URI.');
        }

        if ($method === '' || preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/D', $method) !== 1) {
            throw new InvalidArgumentException('The HTTP method is invalid.');
        }

        $normalized = [];

        foreach ($headers as $name => $value) {
            $name = strtolower($name);

            if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9a-z]+$/D', $name) !== 1) {
                throw new InvalidArgumentException(sprintf('Invalid HTTP header name: "%s".', $name));
            }

            $values = is_array($value) ? $value : [$value];

            if ($values === [] || array_filter($values, 'is_string') !== $values) {
                throw new InvalidArgumentException(sprintf('Invalid value for HTTP header "%s".', $name));
            }

            $normalized[$name] = implode(', ', array_map(
                static fn (string $item): string => trim($item, " \t"),
                $values,
            ));
        }

        $this->normalizedHeaders = $normalized;
    }

    public function header(string $name): ?string
    {
        return $this->normalizedHeaders[strtolower($name)] ?? null;
    }

    public function component(string $name): ?string
    {
        $parts = parse_url($this->targetUri);
        \assert(is_array($parts));

        return match ($name) {
            '@method' => $this->method,
            '@target-uri' => $this->normalizedTargetUri($parts),
            '@authority' => $this->authority($parts),
            '@scheme' => strtolower((string) $parts['scheme']),
            '@path' => isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/',
            '@query' => isset($parts['query']) ? '?'.$parts['query'] : '?',
            default => str_starts_with($name, '@') ? null : $this->header($name),
        };
    }

    /**
     * @param array<string, mixed> $parts
     */
    private function normalizedTargetUri(array $parts): string
    {
        $uri = strtolower((string) $parts['scheme']).'://'.$this->authority($parts);
        $uri .= isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';

        if (isset($parts['query'])) {
            $uri .= '?'.$parts['query'];
        }

        return $uri;
    }

    /**
     * @param array<string, mixed> $parts
     */
    private function authority(array $parts): string
    {
        $host = strtolower((string) $parts['host']);

        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '['.$host.']';
        }

        $scheme = strtolower((string) $parts['scheme']);
        $port = $parts['port'] ?? null;
        $isDefaultPort = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);

        return $host.($port !== null && !$isDefaultPort ? ':'.$port : '');
    }
}
