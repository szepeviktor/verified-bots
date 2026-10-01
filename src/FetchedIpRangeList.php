<?php

declare(strict_types=1);

namespace VerifiedBots;

final readonly class FetchedIpRangeList
{
    /**
     * @param list<string> $cidrs
     */
    public function __construct(
        public array $cidrs,
        public int $cacheTtl,
    ) {
    }
}
