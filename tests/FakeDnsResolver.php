<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use VerifiedBots\DnsResolver;

final class FakeDnsResolver implements DnsResolver
{
    public int $reverseCalls = 0;
    public int $forwardCalls = 0;

    /**
     * @param array<string, string|null> $reverseRecords
     * @param array<string, list<string>> $forwardRecords
     */
    public function __construct(
        private readonly array $reverseRecords = [],
        private readonly array $forwardRecords = [],
    ) {}

    public function reverse(string $ipAddress): ?string
    {
        $this->reverseCalls++;

        return $this->reverseRecords[$ipAddress] ?? null;
    }

    public function forward(string $hostname): array
    {
        $this->forwardCalls++;

        return $this->forwardRecords[$hostname] ?? [];
    }
}
