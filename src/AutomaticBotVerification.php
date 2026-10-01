<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;

final readonly class AutomaticBotVerification
{
    public const WEB_BOT_AUTH = 'web-bot-auth';
    public const IP_RANGE = 'ip-range';
    public const DNS = 'dns';

    public string $name;

    public string $ipAddress;

    public function __construct(
        public string $method,
        public VerifiedWebBot|VerifiedIpRangeBot|VerifiedBot $evidence,
        string $ipAddress,
    ) {
        if (!in_array($method, [self::WEB_BOT_AUTH, self::IP_RANGE, self::DNS], true)) {
            throw new InvalidArgumentException('Unknown bot verification method.');
        }

        $this->name = $evidence instanceof VerifiedWebBot
            ? $evidence->signatureAgent
            : $evidence->name;
        $this->ipAddress = $ipAddress;
    }
}
