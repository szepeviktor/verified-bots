<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;
use Psr\SimpleCache\CacheException;
use Psr\SimpleCache\CacheInterface;

/**
 * Resolves a Signature-Agent on the first cache miss and reuses the JWKS for
 * subsequent requests.
 */
final readonly class RemoteJwksKeyStore implements WebBotAuthKeyStore
{
    public const CACHE_TTL = 86400;
    public const FAILURE_CACHE_TTL = 60;

    public function __construct(
        private CacheInterface $cache,
        private WebBotAuthJwksFetcher $fetcher = new SecureWebBotAuthJwksFetcher(),
        private int $cacheTtl = self::CACHE_TTL,
        private int $failureCacheTtl = self::FAILURE_CACHE_TTL,
    ) {
        if ($cacheTtl < 0 || $failureCacheTtl < 0) {
            throw new InvalidArgumentException('JWKS cache TTL values cannot be negative.');
        }
    }

    public function find(string $signatureAgent, string $discoveryType, string $keyId): ?WebBotAuthKey
    {
        $cacheKey = 'verified-bots.web-bot-auth.'.hash('sha256', $discoveryType."\0".$signatureAgent);
        $cached = $this->read($cacheKey);

        if (is_array($cached) && ($cached['found'] ?? null) === false) {
            return null;
        }

        $document = is_array($cached) && is_array($cached['document'] ?? null)
            ? $cached['document']
            : null;

        if ($document === null) {
            $fetched = $this->fetcher->fetch($signatureAgent, $discoveryType);

            if ($fetched === null) {
                $this->write($cacheKey, ['found' => false], $this->failureCacheTtl);

                return null;
            }

            $document = $fetched->document;
            $ttl = min($this->cacheTtl, $fetched->cacheTtl);
            $this->write($cacheKey, ['found' => true, 'document' => $document], $ttl);
        }

        try {
            return (new JwksKeyStore([$signatureAgent => $document]))
                ->find($signatureAgent, $discoveryType, $keyId);
        } catch (\JsonException|\InvalidArgumentException) {
            $this->write($cacheKey, ['found' => false], $this->failureCacheTtl);

            return null;
        }
    }

    private function read(string $key): mixed
    {
        try {
            return $this->cache->get($key);
        } catch (CacheException) {
            return null;
        }
    }

    /**
     * @param array<string, mixed> $value
     */
    private function write(string $key, array $value, int $ttl): void
    {
        if ($ttl <= 0) {
            return;
        }

        try {
            $this->cache->set($key, $value, $ttl);
        } catch (CacheException) {
            // Verification still works when caching fails; the next request retries discovery.
        }
    }
}
