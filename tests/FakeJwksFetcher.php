<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use VerifiedBots\FetchedWebBotAuthJwks;
use VerifiedBots\WebBotAuthJwksFetcher;

final class FakeJwksFetcher implements WebBotAuthJwksFetcher
{
    public int $calls = 0;

    public function __construct(
        private readonly ?FetchedWebBotAuthJwks $result,
    ) {}

    public function fetch(string $signatureAgent, string $discoveryType): ?FetchedWebBotAuthJwks
    {
        $this->calls++;

        return $this->result;
    }
}
