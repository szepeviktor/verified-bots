<?php

declare(strict_types=1);

namespace VerifiedBots;

final readonly class VerifiedWebBot
{
    public function __construct(
        public string $signatureAgent,
        public string $keyId,
        public string $signatureLabel,
    ) {}
}
