<?php

declare(strict_types=1);

namespace VerifiedBots;

interface WebBotAuthKeyStore
{
    public function find(
        string $signatureAgent,
        string $discoveryType,
        string $keyId,
    ): ?WebBotAuthKey;
}
