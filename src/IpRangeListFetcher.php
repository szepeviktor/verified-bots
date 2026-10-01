<?php

declare(strict_types=1);

namespace VerifiedBots;

interface IpRangeListFetcher
{
    public function fetch(string $url): ?FetchedIpRangeList;
}
