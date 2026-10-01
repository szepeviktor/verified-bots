<?php

declare(strict_types=1);

namespace VerifiedBots;

use Psr\SimpleCache\CacheException;
use Psr\SimpleCache\CacheInterface;

final class BotVerifier
{
    public const CACHE_TTL = 604800;

    /** @var non-empty-list<BotDefinition> */
    private array $definitions;

    private string $definitionHash;

    /**
     * @param non-empty-list<BotDefinition>|null $definitions
     */
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly DnsResolver $dns = new NativeDnsResolver(),
        ?array $definitions = null,
    ) {
        $this->definitions = $definitions ?? self::defaultDefinitions();
        $this->definitionHash = substr(hash('sha256', serialize($this->definitions)), 0, 16);
    }

    public function isVerified(string $ipAddress): bool
    {
        return $this->identify($ipAddress) !== null;
    }

    public function identify(string $ipAddress): ?VerifiedBot
    {
        if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $ipAddress = $this->normalizeIpAddress($ipAddress);
        $cacheKey = 'verified-bots.'.$this->definitionHash.'.'.hash('sha256', $ipAddress);
        $cached = $this->readCache($cacheKey);

        if ($cached !== null) {
            return $this->botFromCache($cached, $ipAddress);
        }

        $bot = $this->resolve($ipAddress);
        $this->writeCache($cacheKey, [
            'found' => $bot !== null,
            'name' => $bot?->name,
            'hostname' => $bot?->hostname,
        ]);

        return $bot;
    }

    /**
     * @return non-empty-list<BotDefinition>
     */
    public static function defaultDefinitions(): array
    {
        return [
            new BotDefinition('Googlebot', ['googlebot.com']),
            new BotDefinition('Bingbot', ['search.msn.com']),
            new BotDefinition('Applebot', ['applebot.apple.com']),
        ];
    }

    private function resolve(string $ipAddress): ?VerifiedBot
    {
        $hostname = $this->dns->reverse($ipAddress);

        if ($hostname === null) {
            return null;
        }

        $hostname = strtolower(rtrim($hostname, '.'));

        foreach ($this->definitions as $definition) {
            if (!$definition->matches($hostname)) {
                continue;
            }

            foreach ($this->dns->forward($hostname) as $resolvedIp) {
                if ($this->sameIpAddress($ipAddress, $resolvedIp)) {
                    return new VerifiedBot($definition->name, $ipAddress, $hostname);
                }
            }

            return null;
        }

        return null;
    }

    /**
     * @return array{found: bool, name: ?string, hostname: ?string}|null
     */
    private function readCache(string $key): ?array
    {
        try {
            $value = $this->cache->get($key);
        } catch (CacheException) {
            return null;
        }

        if (!is_array($value)
            || !isset($value['found'])
            || !is_bool($value['found'])
            || !array_key_exists('name', $value)
            || !array_key_exists('hostname', $value)
        ) {
            return null;
        }

        return $value;
    }

    /**
     * @param array{found: bool, name: ?string, hostname: ?string} $cached
     */
    private function botFromCache(array $cached, string $ipAddress): ?VerifiedBot
    {
        if (!$cached['found'] || !is_string($cached['name']) || !is_string($cached['hostname'])) {
            return null;
        }

        return new VerifiedBot($cached['name'], $ipAddress, $cached['hostname']);
    }

    /**
     * @param array{found: bool, name: ?string, hostname: ?string} $value
     */
    private function writeCache(string $key, array $value): void
    {
        try {
            $this->cache->set($key, $value, self::CACHE_TTL);
        } catch (CacheException) {
            // DNS verification remains usable when the cache backend is unavailable.
        }
    }

    private function sameIpAddress(string $first, string $second): bool
    {
        $firstBinary = @inet_pton($first);
        $secondBinary = @inet_pton($second);

        return $firstBinary !== false
            && $secondBinary !== false
            && hash_equals($firstBinary, $secondBinary);
    }

    private function normalizeIpAddress(string $ipAddress): string
    {
        $binary = inet_pton($ipAddress);

        return $binary === false ? $ipAddress : (inet_ntop($binary) ?: $ipAddress);
    }
}
