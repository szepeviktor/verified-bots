<?php

declare(strict_types=1);

namespace VerifiedBots;

final class CidrMatcher
{
    public static function matches(string $ipAddress, string $cidr): bool
    {
        $ip = inet_pton($ipAddress);
        $normalized = self::normalize($cidr);

        if ($ip === false || $normalized === null) {
            return false;
        }

        [$networkAddress, $prefixLength] = explode('/', $normalized, 2);
        $network = inet_pton($networkAddress);

        if ($network === false || strlen($ip) !== strlen($network)) {
            return false;
        }

        $bits = (int) $prefixLength;
        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        if ($wholeBytes > 0
            && substr($ip, 0, $wholeBytes) !== substr($network, 0, $wholeBytes)
        ) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xff << (8 - $remainingBits)) & 0xff;

        return (ord($ip[$wholeBytes]) & $mask) === (ord($network[$wholeBytes]) & $mask);
    }

    public static function normalize(string $cidr): ?string
    {
        if (substr_count($cidr, '/') !== 1) {
            return null;
        }

        [$address, $rawPrefix] = explode('/', $cidr, 2);

        if ($rawPrefix === '' || !ctype_digit($rawPrefix)) {
            return null;
        }

        $packed = inet_pton($address);

        if ($packed === false) {
            return null;
        }

        $prefix = (int) $rawPrefix;
        $maximum = strlen($packed) * 8;

        if ($prefix > $maximum) {
            return null;
        }

        $network = $packed;
        $wholeBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;

        if ($remainingBits !== 0) {
            $network[$wholeBytes] = chr(
                ord($network[$wholeBytes]) & ((0xff << (8 - $remainingBits)) & 0xff),
            );
            ++$wholeBytes;
        }

        for ($index = $wholeBytes; $index < strlen($network); ++$index) {
            $network[$index] = "\0";
        }

        $normalizedAddress = inet_ntop($network);

        return $normalizedAddress === false ? null : $normalizedAddress.'/'.$prefix;
    }
}
