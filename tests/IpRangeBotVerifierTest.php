<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VerifiedBots\CidrMatcher;
use VerifiedBots\FetchedIpRangeList;
use VerifiedBots\IpRangeBotDefinition;
use VerifiedBots\IpRangeBotVerifier;
use VerifiedBots\JsonIpRangeBotDefinitionLoader;

final class IpRangeBotVerifierTest extends TestCase
{
    private const SOURCE = 'https://crawler.example/ip-ranges.json';

    #[DataProvider('cidrCases')]
    public function testMatchesIpv4AndIpv6Cidrs(string $ip, string $cidr, bool $expected): void
    {
        self::assertSame($expected, CidrMatcher::matches($ip, $cidr));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function cidrCases(): iterable
    {
        yield 'IPv4 inside' => ['192.0.2.42', '192.0.2.0/24', true];
        yield 'IPv4 outside' => ['192.0.3.1', '192.0.2.0/24', false];
        yield 'IPv6 inside' => ['2001:db8:abcd::1', '2001:db8:abcd::/48', true];
        yield 'IPv6 outside' => ['2001:db8:abce::1', '2001:db8:abcd::/48', false];
        yield 'different address families' => ['192.0.2.1', '2001:db8::/32', false];
        yield 'invalid prefix' => ['192.0.2.1', '192.0.2.0/33', false];
    }

    public function testIdentifiesMatchingIpAndUserAgentAndCachesFeed(): void
    {
        $cache = new InMemoryCache();
        $fetcher = new FakeIpRangeListFetcher([
            self::SOURCE => new FetchedIpRangeList(['192.0.2.0/24', '2001:db8::/32'], 7200),
        ]);
        $verifier = new IpRangeBotVerifier(
            $cache,
            $fetcher,
            [new IpRangeBotDefinition('ExampleBot', ['ExampleBot'], self::SOURCE)],
        );

        $bot = $verifier->identify('192.0.2.42', 'Mozilla/5.0 ExampleBot/1.0');

        self::assertNotNull($bot);
        self::assertSame('ExampleBot', $bot->name);
        self::assertSame('192.0.2.0/24', $bot->matchedCidr);
        self::assertTrue($verifier->isVerified('2001:db8::42', 'ExampleBot'));
        self::assertSame(1, $fetcher->calls);
        self::assertContains(7200, $cache->ttls);
    }

    public function testRequiresBothUserAgentAndAddressMatch(): void
    {
        $fetcher = new FakeIpRangeListFetcher([
            self::SOURCE => new FetchedIpRangeList(['192.0.2.0/24'], 3600),
        ]);
        $verifier = new IpRangeBotVerifier(
            new InMemoryCache(),
            $fetcher,
            [new IpRangeBotDefinition('ExampleBot', ['ExampleBot'], self::SOURCE)],
        );

        self::assertNull($verifier->identify('192.0.2.42', 'NotTheBot/1.0'));
        self::assertNull($verifier->identify('198.51.100.42', 'ExampleBot/1.0'));
        self::assertSame(1, $fetcher->calls);
    }

    public function testLoadsBundledJsonDefinitions(): void
    {
        $definitions = JsonIpRangeBotDefinitionLoader::defaults();

        self::assertSame(['Applebot', 'Bingbot', 'Googlebot'], array_column($definitions, 'name'));
        self::assertContains(
            'https://search.developer.apple.com/applebot.json',
            array_column($definitions, 'sourceUrl'),
        );
    }

    public function testCachesFailedFetchBriefly(): void
    {
        $cache = new InMemoryCache();
        $fetcher = new FakeIpRangeListFetcher([]);
        $verifier = new IpRangeBotVerifier(
            $cache,
            $fetcher,
            [new IpRangeBotDefinition('ExampleBot', ['ExampleBot'], self::SOURCE)],
        );

        self::assertNull($verifier->identify('192.0.2.42', 'ExampleBot'));
        self::assertNull($verifier->identify('192.0.2.42', 'ExampleBot'));
        self::assertSame(1, $fetcher->calls);
        self::assertContains(IpRangeBotVerifier::NEGATIVE_CACHE_TTL, $cache->ttls);
    }
}
