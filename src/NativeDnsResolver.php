<?php

declare(strict_types=1);

namespace VerifiedBots;

final class NativeDnsResolver implements DnsResolver
{
    public function reverse(string $ipAddress): ?string
    {
        $hostname = gethostbyaddr($ipAddress);

        if ($hostname === false || $hostname === $ipAddress) {
            return null;
        }

        return strtolower(rtrim($hostname, '.'));
    }

    public function forward(string $hostname): array
    {
        $records = dns_get_record($hostname, DNS_A | DNS_AAAA);

        if ($records === false) {
            return [];
        }

        $addresses = [];

        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;

            if (is_string($address) && filter_var($address, FILTER_VALIDATE_IP) !== false) {
                $addresses[] = $address;
            }
        }

        return array_values(array_unique($addresses));
    }
}
