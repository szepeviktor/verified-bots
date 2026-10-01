<?php

declare(strict_types=1);

namespace VerifiedBots;

interface WebBotAuthJwksFetcher
{
    public function fetch(string $signatureAgent, string $discoveryType): ?FetchedWebBotAuthJwks;
}
