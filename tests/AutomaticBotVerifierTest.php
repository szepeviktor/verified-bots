<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use PHPUnit\Framework\TestCase;
use VerifiedBots\AutomaticBotVerification;
use VerifiedBots\AutomaticBotVerifier;
use VerifiedBots\BotVerifier;
use VerifiedBots\BotVerificationStatus;
use VerifiedBots\FetchedIpRangeList;
use VerifiedBots\IpRangeBotDefinition;
use VerifiedBots\IpRangeBotVerifier;
use VerifiedBots\JwksKeyStore;
use VerifiedBots\WebBotAuthRequest;
use VerifiedBots\WebBotAuthVerifier;

final class AutomaticBotVerifierTest extends TestCase
{
    private const SOURCE = 'https://crawler.example/ip-ranges.json';

    public function testHttpEntryPointAutomaticallyUsesIpRangesBeforeDns(): void
    {
        $cache = new InMemoryCache();
        $dnsResolver = new FakeDnsResolver();
        $ipRanges = new IpRangeBotVerifier(
            $cache,
            new FakeIpRangeListFetcher([
                self::SOURCE => new FetchedIpRangeList(['192.0.2.0/24'], 3600),
            ]),
            [new IpRangeBotDefinition('ExampleBot', ['ExampleBot'], self::SOURCE)],
        );
        $verifier = new AutomaticBotVerifier(
            $cache,
            ipRanges: $ipRanges,
            dns: new BotVerifier($cache, $dnsResolver),
        );

        $result = $verifier->identifyHttp(
            '192.0.2.42',
            'GET',
            'https://example.com/articles',
            ['User-Agent' => 'ExampleBot/1.0'],
        );

        self::assertNotNull($result);
        self::assertSame(AutomaticBotVerification::IP_RANGE, $result->method);
        self::assertSame('ExampleBot', $result->name);
        self::assertSame(0, $dnsResolver->reverseCalls);
    }

    public function testGlobalsEntryPointNeedsNoArguments(): void
    {
        $cache = new InMemoryCache();
        $ipRanges = new IpRangeBotVerifier(
            $cache,
            new FakeIpRangeListFetcher([
                self::SOURCE => new FetchedIpRangeList(['192.0.2.0/24'], 3600),
            ]),
            [new IpRangeBotDefinition('ExampleBot', ['ExampleBot'], self::SOURCE)],
        );
        $verifier = new AutomaticBotVerifier(
            $cache,
            ipRanges: $ipRanges,
            enableWebBotAuth: false,
            enableDns: false,
        );

        $server = [
            'REMOTE_ADDR' => '192.0.2.42',
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'example.com',
            'REQUEST_URI' => '/articles?page=2',
            'HTTPS' => 'on',
            'HTTP_USER_AGENT' => 'ExampleBot/1.0',
        ];
        $result = $verifier->identifyGlobals($server, []);

        self::assertNotNull($result);
        self::assertSame(AutomaticBotVerification::IP_RANGE, $result->method);
        self::assertSame('ExampleBot', $result->name);
    }

    public function testGlobalsStillChecksDnsWhenHttpUrlCannotBeBuilt(): void
    {
        $ip = '192.0.2.42';
        $hostname = 'crawler.example.com';
        $cache = new InMemoryCache();
        $dns = new BotVerifier(
            $cache,
            new FakeDnsResolver([$ip => $hostname], [$hostname => [$ip]]),
            [new \VerifiedBots\BotDefinition('ExampleBot', ['example.com'])],
        );
        $verifier = new AutomaticBotVerifier(
            $cache,
            dns: $dns,
            enableIpRanges: false,
        );

        $result = $verifier->identifyGlobals(['REMOTE_ADDR' => $ip], []);

        self::assertNotNull($result);
        self::assertSame(AutomaticBotVerification::DNS, $result->method);
    }

    public function testItFallsBackToDnsWhenThereIsNoIpRangeMatch(): void
    {
        $ip = '192.0.2.42';
        $hostname = 'crawler.example.com';
        $cache = new InMemoryCache();
        $dnsResolver = new FakeDnsResolver([$ip => $hostname], [$hostname => [$ip]]);
        $dns = new BotVerifier(
            $cache,
            $dnsResolver,
            [new \VerifiedBots\BotDefinition('ExampleBot', ['example.com'])],
        );
        $ipRanges = new IpRangeBotVerifier(
            $cache,
            new FakeIpRangeListFetcher([]),
            [new IpRangeBotDefinition('OtherBot', ['OtherBot'], self::SOURCE)],
        );
        $verifier = new AutomaticBotVerifier($cache, ipRanges: $ipRanges, dns: $dns);

        $result = $verifier->identify($ip, 'UnknownBot/1.0');

        self::assertNotNull($result);
        self::assertSame(AutomaticBotVerification::DNS, $result->method);
        self::assertSame('ExampleBot', $result->name);
    }

    public function testWebBotAuthHasFirstPriorityWhenItsSignatureIsValid(): void
    {
        $keyId = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
        $input = '("@authority" "signature-agent";key="agent2")'
            .';created=1735689600'
            .';keyid="'.$keyId.'"'
            .';alg="ed25519"'
            .';expires=4889289600'
            .';nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="'
            .';tag="web-bot-auth"';
        $request = new WebBotAuthRequest('GET', 'https://example.com/', [
            'Signature-Agent' => 'agent2="https://signature-agent.test"',
            'Signature-Input' => 'sig2='.$input,
            'Signature' => 'sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:',
        ]);
        $keys = new JwksKeyStore([
            'https://signature-agent.test' => [
                'keys' => [[
                    'kty' => 'OKP',
                    'crv' => 'Ed25519',
                    'x' => 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
                    'kid' => $keyId,
                ]],
            ],
        ]);
        $cache = new InMemoryCache();
        $verifier = new AutomaticBotVerifier(
            $cache,
            webBotAuth: new WebBotAuthVerifier($keys, maximumValidity: 3153600000),
            enableIpRanges: false,
            enableDns: false,
        );

        $result = $verifier->identify(
            '192.0.2.42',
            request: $request,
            now: 1735689600,
        );

        self::assertNotNull($result);
        self::assertSame(AutomaticBotVerification::WEB_BOT_AUTH, $result->method);
        self::assertSame('https://signature-agent.test', $result->name);
    }

    public function testChecksCanBeDisabledWithNamedParameters(): void
    {
        $ip = '192.0.2.42';
        $hostname = 'crawler.example.com';
        $cache = new InMemoryCache();
        $dns = new BotVerifier(
            $cache,
            new FakeDnsResolver([$ip => $hostname], [$hostname => [$ip]]),
            [new \VerifiedBots\BotDefinition('ExampleBot', ['example.com'])],
        );
        $verifier = new AutomaticBotVerifier(
            $cache,
            dns: $dns,
            enableWebBotAuth: false,
            enableIpRanges: false,
            enableDns: false,
        );

        self::assertFalse($verifier->isVerified($ip));
    }

    public function testInvalidIpStopsEveryCheck(): void
    {
        $cache = new InMemoryCache();
        $dnsResolver = new FakeDnsResolver();
        $verifier = new AutomaticBotVerifier(
            $cache,
            dns: new BotVerifier($cache, $dnsResolver),
            enableWebBotAuth: false,
            enableIpRanges: false,
        );

        self::assertNull($verifier->identify('not-an-ip'));
        self::assertSame(0, $dnsResolver->reverseCalls);
    }

    public function testClassifiesVerifiedSpoofedAndUnknownRequests(): void
    {
        $cache = new InMemoryCache();
        $ipRanges = new IpRangeBotVerifier(
            $cache,
            new FakeIpRangeListFetcher([
                self::SOURCE => new FetchedIpRangeList(['192.0.2.0/24'], 3600),
            ]),
            [new IpRangeBotDefinition('ExampleBot', ['ExampleBot'], self::SOURCE)],
        );
        $verifier = new AutomaticBotVerifier(
            $cache,
            ipRanges: $ipRanges,
            dns: new BotVerifier($cache, new FakeDnsResolver()),
        );

        self::assertSame(
            BotVerificationStatus::VERIFIED,
            $verifier->classify('192.0.2.42', 'ExampleBot/1.0'),
        );
        self::assertSame(
            BotVerificationStatus::SPOOFED,
            $verifier->classify('198.51.100.42', 'ExampleBot/1.0'),
        );
        self::assertSame(
            BotVerificationStatus::UNKNOWN,
            $verifier->classify('198.51.100.42', 'Mozilla/5.0'),
        );
    }

    public function testInvalidSignatureAgentClaimIsSpoofed(): void
    {
        $cache = new InMemoryCache();
        $verifier = new AutomaticBotVerifier(
            $cache,
            webBotAuth: new WebBotAuthVerifier(new JwksKeyStore([])),
            enableIpRanges: false,
            enableDns: false,
        );

        $status = $verifier->classifyHttp(
            '192.0.2.42',
            'GET',
            'https://example.com/',
            ['Signature-Agent' => 'agent="https://crawler.example"'],
        );

        self::assertSame(BotVerificationStatus::SPOOFED, $status);
    }

    public function testCustomClaimPatternsCanBeProvided(): void
    {
        $cache = new InMemoryCache();
        $verifier = new AutomaticBotVerifier(
            $cache,
            enableWebBotAuth: false,
            enableIpRanges: false,
            enableDns: false,
            botUserAgentClaims: ['PrivateCrawler'],
        );

        self::assertSame(
            BotVerificationStatus::SPOOFED,
            $verifier->classify('192.0.2.42', 'PrivateCrawler/2.0'),
        );
    }
}
