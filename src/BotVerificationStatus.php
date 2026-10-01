<?php

declare(strict_types=1);

namespace VerifiedBots;

enum BotVerificationStatus: string
{
    case VERIFIED = 'verified';
    case SPOOFED = 'spoofed';
    case UNKNOWN = 'unknown';
}
