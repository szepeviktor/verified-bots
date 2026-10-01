<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;

final readonly class IpRangeBotDefinition
{
    /**
     * @param non-empty-list<string> $userAgentSubstrings
     */
    public function __construct(
        public string $name,
        public array $userAgentSubstrings,
        public string $sourceUrl,
    ) {
        if ($name === '' || $userAgentSubstrings === []) {
            throw new InvalidArgumentException('A bot name and at least one User-Agent substring are required.');
        }

        foreach ($userAgentSubstrings as $substring) {
            if ($substring === '') {
                throw new InvalidArgumentException('User-Agent substrings cannot be empty.');
            }
        }

        $parts = parse_url($sourceUrl);

        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || !is_string($parts['host'] ?? null)
            || (filter_var($parts['host'], FILTER_VALIDATE_IP) === false
                && filter_var($parts['host'], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false)
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
            || isset($parts['port'])
        ) {
            throw new InvalidArgumentException('The IP range source must be an HTTPS URL on port 443.');
        }
    }

    public function matchesUserAgent(string $userAgent): bool
    {
        foreach ($this->userAgentSubstrings as $substring) {
            if (stripos($userAgent, $substring) !== false) {
                return true;
            }
        }

        return false;
    }
}
