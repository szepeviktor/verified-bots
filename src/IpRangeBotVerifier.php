<?php

declare(strict_types=1);

namespace VerifiedBots;

use Psr\SimpleCache\CacheInterface;
use Throwable;

final class IpRangeBotVerifier
{
    public const NEGATIVE_CACHE_TTL = 60;

    /** @var list<IpRangeBotDefinition> */
    private array $definitions;

    private IpRangeListFetcher $fetcher;

    /**
     * @param null|iterable<IpRangeBotDefinition> $definitions
     */
    public function __construct(
        private readonly CacheInterface $cache,
        ?IpRangeListFetcher $fetcher = null,
        ?iterable $definitions = null,
    ) {
        $this->fetcher = $fetcher ?? new SecureJsonIpRangeListFetcher();
        $this->definitions = $definitions === null
            ? JsonIpRangeBotDefinitionLoader::defaults()
            : array_values(iterator_to_array(
                (static function () use ($definitions): iterable {
                    yield from $definitions;
                })(),
                false,
            ));
    }

    public function identify(string $ipAddress, string $userAgent): ?VerifiedIpRangeBot
    {
        $normalizedIp = filter_var($ipAddress, FILTER_VALIDATE_IP);

        if (!is_string($normalizedIp) || $userAgent === '') {
            return null;
        }

        foreach ($this->definitions as $definition) {
            if (!$definition->matchesUserAgent($userAgent)) {
                continue;
            }

            foreach ($this->cidrsFor($definition) as $cidr) {
                if (CidrMatcher::matches($normalizedIp, $cidr)) {
                    return new VerifiedIpRangeBot(
                        $definition->name,
                        $normalizedIp,
                        $cidr,
                        $definition->sourceUrl,
                    );
                }
            }
        }

        return null;
    }

    public function isVerified(string $ipAddress, string $userAgent): bool
    {
        return $this->identify($ipAddress, $userAgent) !== null;
    }

    public function recognizesUserAgent(string $userAgent): bool
    {
        if ($userAgent === '') {
            return false;
        }

        foreach ($this->definitions as $definition) {
            if ($definition->matchesUserAgent($userAgent)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function userAgentSubstrings(): array
    {
        $substrings = [];

        foreach ($this->definitions as $definition) {
            array_push($substrings, ...$definition->userAgentSubstrings);
        }

        return array_values(array_unique($substrings));
    }

    /**
     * @return list<string>
     */
    private function cidrsFor(IpRangeBotDefinition $definition): array
    {
        $key = 'verified-bots.ip-ranges.'.hash('sha256', $definition->sourceUrl);

        try {
            $cached = $this->cache->get($key);
        } catch (Throwable) {
            $cached = null;
        }

        if (is_array($cached)) {
            return array_values(array_filter($cached, static fn (mixed $cidr): bool => is_string($cidr)));
        }

        $fetched = $this->fetcher->fetch($definition->sourceUrl);

        if ($fetched === null) {
            $this->cache($key, [], self::NEGATIVE_CACHE_TTL);

            return [];
        }

        if ($fetched->cacheTtl > 0) {
            $this->cache($key, $fetched->cidrs, $fetched->cacheTtl);
        }

        return $fetched->cidrs;
    }

    /**
     * @param list<string> $cidrs
     */
    private function cache(string $key, array $cidrs, int $ttl): void
    {
        try {
            $this->cache->set($key, $cidrs, $ttl);
        } catch (Throwable) {
            // Verification still works when the cache backend is unavailable.
        }
    }
}
