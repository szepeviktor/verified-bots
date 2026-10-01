<?php

declare(strict_types=1);

namespace VerifiedBots;

final readonly class VerifiedIpRangeBot
{
    public function __construct(
        public string $name,
        public string $ipAddress,
        public string $matchedCidr,
        public string $sourceUrl,
    ) {
    }
}
