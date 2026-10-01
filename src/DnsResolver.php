<?php

declare(strict_types=1);

namespace VerifiedBots;

interface DnsResolver
{
    public function reverse(string $ipAddress): ?string;

    /**
     * @return list<string>
     */
    public function forward(string $hostname): array;
}
