<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use VerifiedBots\FetchedIpRangeList;
use VerifiedBots\IpRangeListFetcher;

final class FakeIpRangeListFetcher implements IpRangeListFetcher
{
    public int $calls = 0;

    /**
     * @param array<string, FetchedIpRangeList> $responses
     */
    public function __construct(private readonly array $responses)
    {
    }

    public function fetch(string $url): ?FetchedIpRangeList
    {
        ++$this->calls;

        return $this->responses[$url] ?? null;
    }
}
