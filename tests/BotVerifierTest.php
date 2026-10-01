<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VerifiedBots\BotDefinition;
use VerifiedBots\BotVerifier;

final class BotVerifierTest extends TestCase
{
    #[DataProvider('verifiedBotProvider')]
    public function testItIdentifiesVerifiedBots(string $name, string $ip, string $hostname): void
    {
        $dns = new FakeDnsResolver(
            [$ip => $hostname.'.'],
            [$hostname => [$ip]],
        );
        $verifier = new BotVerifier(new InMemoryCache(), $dns);

        $bot = $verifier->identify($ip);

        self::assertNotNull($bot);
        self::assertSame($name, $bot->name);
        self::assertSame($ip, $bot->ipAddress);
        self::assertSame($hostname, $bot->hostname);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function verifiedBotProvider(): iterable
    {
        yield 'Googlebot' => ['Googlebot', '66.249.66.1', 'crawl-66-249-66-1.googlebot.com'];
        yield 'Bingbot' => ['Bingbot', '157.55.39.1', 'msnbot-157-55-39-1.search.msn.com'];
        yield 'Applebot' => ['Applebot', '17.58.101.179', '17-58-101-179.applebot.apple.com'];
        yield 'IPv6 Googlebot' => ['Googlebot', '2001:4860:4801:10::1', 'crawl-2001-4860.googlebot.com'];
    }

    public function testItRejectsSpoofedHostnameSuffixes(): void
    {
        $ip = '203.0.113.10';
        $hostname = 'googlebot.com.attacker.test';
        $dns = new FakeDnsResolver([$ip => $hostname], [$hostname => [$ip]]);
        $verifier = new BotVerifier(new InMemoryCache(), $dns);

        self::assertNull($verifier->identify($ip));
        self::assertSame(0, $dns->forwardCalls);
    }

    public function testItRequiresForwardDnsToReturnTheOriginalIp(): void
    {
        $ip = '66.249.66.1';
        $hostname = 'crawl-66-249-66-1.googlebot.com';
        $dns = new FakeDnsResolver([$ip => $hostname], [$hostname => ['203.0.113.20']]);
        $verifier = new BotVerifier(new InMemoryCache(), $dns);

        self::assertFalse($verifier->isVerified($ip));
    }

    public function testItCachesPositiveResultsForOneWeek(): void
    {
        $ip = '66.249.66.1';
        $hostname = 'crawl-66-249-66-1.googlebot.com';
        $cache = new InMemoryCache();
        $dns = new FakeDnsResolver([$ip => $hostname], [$hostname => [$ip]]);
        $verifier = new BotVerifier($cache, $dns);

        self::assertNotNull($verifier->identify($ip));
        self::assertNotNull($verifier->identify($ip));

        self::assertSame(1, $dns->reverseCalls);
        self::assertSame(1, $dns->forwardCalls);
        self::assertSame([BotVerifier::CACHE_TTL], array_values($cache->ttls));
    }

    public function testItCachesNegativeResultsForOneWeek(): void
    {
        $ip = '203.0.113.10';
        $cache = new InMemoryCache();
        $dns = new FakeDnsResolver([$ip => null]);
        $verifier = new BotVerifier($cache, $dns);

        self::assertNull($verifier->identify($ip));
        self::assertNull($verifier->identify($ip));

        self::assertSame(1, $dns->reverseCalls);
        self::assertSame([BotVerifier::CACHE_TTL], array_values($cache->ttls));
    }

    public function testItRejectsInvalidIpWithoutDnsOrCacheWork(): void
    {
        $cache = new InMemoryCache();
        $dns = new FakeDnsResolver();
        $verifier = new BotVerifier($cache, $dns);

        self::assertNull($verifier->identify('not-an-ip'));
        self::assertSame(0, $dns->reverseCalls);
        self::assertSame([], $cache->values);
    }

    public function testDefinitionsCanBeCustomized(): void
    {
        $ip = '192.0.2.10';
        $hostname = 'crawler.example.com';
        $dns = new FakeDnsResolver([$ip => $hostname], [$hostname => [$ip]]);
        $verifier = new BotVerifier(
            new InMemoryCache(),
            $dns,
            [new BotDefinition('ExampleBot', ['example.com'])],
        );

        self::assertSame('ExampleBot', $verifier->identify($ip)?->name);
    }
}
