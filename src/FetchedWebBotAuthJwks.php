<?php

declare(strict_types=1);

namespace VerifiedBots;

final readonly class FetchedWebBotAuthJwks
{
    /**
     * @param array<string, mixed> $document
     */
    public function __construct(
        public array $document,
        public int $cacheTtl,
    ) {}
}
