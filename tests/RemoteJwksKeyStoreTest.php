<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use PHPUnit\Framework\TestCase;
use VerifiedBots\FetchedWebBotAuthJwks;
use VerifiedBots\RemoteJwksKeyStore;
use VerifiedBots\SecureWebBotAuthJwksFetcher;
use VerifiedBots\WebBotAuthKey;

final class RemoteJwksKeyStoreTest extends TestCase
{
    private const AGENT = 'https://crawler.example';

    public function testItFetchesOnTheFirstVisitAndUsesTheCacheAfterThat(): void
    {
        $key = $this->key();
        $fetcher = new FakeJwksFetcher(new FetchedWebBotAuthJwks(
            $this->document($key),
            7200,
        ));
        $cache = new InMemoryCache();
        $store = new RemoteJwksKeyStore($cache, $fetcher);

        self::assertSame($key->id, $store->find(self::AGENT, 'directory', $key->id)?->id);
        self::assertSame($key->id, $store->find(self::AGENT, 'directory', $key->id)?->id);
        self::assertSame(1, $fetcher->calls);
        self::assertSame([7200], array_values($cache->ttls));
    }

    public function testItNegativelyCachesDiscoveryFailures(): void
    {
        $fetcher = new FakeJwksFetcher(null);
        $cache = new InMemoryCache();
        $store = new RemoteJwksKeyStore($cache, $fetcher);

        self::assertNull($store->find(self::AGENT, 'directory', 'unknown'));
        self::assertNull($store->find(self::AGENT, 'directory', 'unknown'));
        self::assertSame(1, $fetcher->calls);
        self::assertSame(
            [RemoteJwksKeyStore::FAILURE_CACHE_TTL],
            array_values($cache->ttls),
        );
    }

    public function testSecureFetcherRejectsPrivateDestinationsBeforeConnecting(): void
    {
        $fetcher = new SecureWebBotAuthJwksFetcher(
            new FakeDnsResolver(forwardRecords: ['crawler.example' => ['127.0.0.1']]),
        );

        self::assertNull($fetcher->fetch(self::AGENT, 'directory'));
    }

    private function key(): WebBotAuthKey
    {
        $pair = sodium_crypto_sign_keypair();
        $x = rtrim(strtr(base64_encode(sodium_crypto_sign_publickey($pair)), '+/', '-_'), '=');

        return new WebBotAuthKey($x);
    }

    /**
     * @return array{keys: list<array{kty: string, crv: string, x: string, kid: string}>}
     */
    private function document(WebBotAuthKey $key): array
    {
        return [
            'keys' => [[
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'x' => $key->x,
                'kid' => $key->id,
            ]],
        ];
    }
}
