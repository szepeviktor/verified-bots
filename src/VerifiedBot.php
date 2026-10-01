<?php

declare(strict_types=1);

namespace VerifiedBots;

final readonly class VerifiedBot
{
    public function __construct(
        public string $name,
        public string $ipAddress,
        public string $hostname,
    ) {}
}
