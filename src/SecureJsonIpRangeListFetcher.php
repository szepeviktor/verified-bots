<?php

declare(strict_types=1);

namespace VerifiedBots;

use CurlHandle;
use InvalidArgumentException;
use JsonException;

final readonly class SecureJsonIpRangeListFetcher implements IpRangeListFetcher
{
    public const MAX_RESPONSE_BYTES = 1048576;
    public const MAX_PREFIXES = 10000;
    public const TIMEOUT_MILLISECONDS = 5000;
    public const DEFAULT_CACHE_TTL = 3600;
    public const MAX_CACHE_TTL = 86400;

    public function __construct(
        private DnsResolver $dns = new NativeDnsResolver(),
        private int $maximumResponseBytes = self::MAX_RESPONSE_BYTES,
        private int $timeoutMilliseconds = self::TIMEOUT_MILLISECONDS,
    ) {
        if ($maximumResponseBytes < 1024 || $timeoutMilliseconds < 1) {
            throw new InvalidArgumentException('IP range feed limits must be positive.');
        }
    }

    public function fetch(string $url): ?FetchedIpRangeList
    {
        $parts = parse_url($url);

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
            return null;
        }

        $host = $parts['host'];
        $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false
            ? [$host]
            : $this->dns->forward($host);
        $address = $this->firstPublicAddress($addresses);

        if ($address === null) {
            return null;
        }

        $body = '';
        $contentType = null;
        $cacheControl = null;
        $age = 0;
        $curl = curl_init();

        if (!$curl instanceof CurlHandle) {
            return null;
        }

        $resolveAddress = str_contains($address, ':') ? '['.$address.']' : $address;

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_HTTPGET => true,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => min(2000, $this->timeoutMilliseconds),
            CURLOPT_TIMEOUT_MS => $this->timeoutMilliseconds,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROXY => '',
            CURLOPT_RESOLVE => [sprintf('%s:443:%s', $host, $resolveAddress)],
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'User-Agent: verified-bots-ip-ranges/1',
            ],
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (
                &$contentType,
                &$cacheControl,
                &$age,
            ): int {
                if (stripos($line, 'Content-Type:') === 0) {
                    $contentType = strtolower(trim(explode(';', substr($line, 13), 2)[0]));
                } elseif (stripos($line, 'Cache-Control:') === 0) {
                    $cacheControl = strtolower(trim(substr($line, 14)));
                } elseif (stripos($line, 'Age:') === 0) {
                    $rawAge = trim(substr($line, 4));
                    $age = ctype_digit($rawAge) ? (int) $rawAge : 0;
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > $this->maximumResponseBytes) {
                    return 0;
                }

                $body .= $chunk;

                return strlen($chunk);
            },
        ]);

        $success = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);

        if ($success === false
            || $status !== 200
            || $contentType !== 'application/json'
            || $body === ''
        ) {
            return null;
        }

        try {
            $document = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        $cidrs = $this->extractCidrs($document);

        if ($cidrs === null) {
            return null;
        }

        return new FetchedIpRangeList($cidrs, $this->cacheTtl($cacheControl, $age));
    }

    /**
     * @return null|list<string>
     */
    private function extractCidrs(mixed $document): ?array
    {
        if (!is_array($document)
            || !is_array($document['prefixes'] ?? null)
            || $document['prefixes'] === []
            || count($document['prefixes']) > self::MAX_PREFIXES
        ) {
            return null;
        }

        $cidrs = [];

        foreach ($document['prefixes'] as $prefix) {
            if (!is_array($prefix)) {
                return null;
            }

            $raw = $prefix['ipv4Prefix'] ?? $prefix['ipv6Prefix'] ?? null;
            $normalized = is_string($raw) ? CidrMatcher::normalize($raw) : null;

            if ($normalized === null) {
                return null;
            }

            $cidrs[] = $normalized;
        }

        return array_values(array_unique($cidrs));
    }

    /**
     * @param list<string> $addresses
     */
    private function firstPublicAddress(array $addresses): ?string
    {
        foreach ($addresses as $address) {
            if (filter_var(
                $address,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            ) !== false) {
                return $address;
            }
        }

        return null;
    }

    private function cacheTtl(?string $cacheControl, int $age): int
    {
        if ($cacheControl !== null
            && preg_match('/(?:^|,)\s*no-(?:store|cache)(?:\s*,|$)/', $cacheControl) === 1
        ) {
            return 0;
        }

        $ttl = self::DEFAULT_CACHE_TTL;

        if ($cacheControl !== null
            && preg_match('/(?:^|,)\s*max-age\s*=\s*"?([0-9]+)"?/', $cacheControl, $match) === 1
        ) {
            $ttl = (int) $match[1];
        }

        return max(0, min(self::MAX_CACHE_TTL, $ttl) - $age);
    }
}
