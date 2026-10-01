<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;
use Psr\SimpleCache\CacheInterface;

/**
 * Tries every supported verification mechanism through one entry point.
 *
 * Custom verifier instances can be injected for advanced configuration, while
 * the defaults work with only a PSR-16 cache.
 */
final class AutomaticBotVerifier
{
    private ?WebBotAuthVerifier $webBotAuth;

    private ?IpRangeBotVerifier $ipRanges;

    private ?BotVerifier $dns;

    /** @var list<string> */
    private array $botUserAgentClaims;

    /**
     * @param null|list<string> $botUserAgentClaims
     */
    public function __construct(
        CacheInterface $cache,
        ?WebBotAuthVerifier $webBotAuth = null,
        ?IpRangeBotVerifier $ipRanges = null,
        ?BotVerifier $dns = null,
        bool $enableWebBotAuth = true,
        bool $enableIpRanges = true,
        bool $enableDns = true,
        ?array $botUserAgentClaims = null,
    ) {
        $configuredIpRanges = $ipRanges ?? new IpRangeBotVerifier($cache);
        $this->webBotAuth = $enableWebBotAuth
            ? ($webBotAuth ?? new WebBotAuthVerifier(new RemoteJwksKeyStore($cache)))
            : null;
        $this->ipRanges = $enableIpRanges
            ? $configuredIpRanges
            : null;
        $this->dns = $enableDns
            ? ($dns ?? new BotVerifier($cache))
            : null;
        $this->botUserAgentClaims = $botUserAgentClaims
            ?? $configuredIpRanges->userAgentSubstrings();

        foreach ($this->botUserAgentClaims as $claim) {
            if (!is_string($claim) || $claim === '') {
                throw new InvalidArgumentException('Bot User-Agent claim patterns must be non-empty strings.');
            }
        }
    }

    /**
     * Runs all applicable checks for an HTTP request.
     *
     * @param array<string, string|list<string>> $headers
     */
    public function identifyHttp(
        string $ipAddress,
        string $method,
        string $targetUri,
        array $headers = [],
        ?int $now = null,
    ): ?AutomaticBotVerification {
        $request = new WebBotAuthRequest($method, $targetUri, $headers);

        return $this->identify(
            $ipAddress,
            $request->header('user-agent') ?? '',
            $request,
            $now,
        );
    }

    /**
     * Convenience entry point for traditional PHP applications.
     *
     * Explicit arrays are accepted to make adapters and tests independent of
     * process-wide globals. Without them, $_SERVER and getallheaders() are used.
     *
     * @param null|array<string, mixed> $server
     * @param null|array<string, string|list<string>> $headers
     */
    public function identifyGlobals(
        ?array $server = null,
        ?array $headers = null,
        ?int $now = null,
    ): ?AutomaticBotVerification {
        $server ??= $_SERVER;
        $headers ??= $this->globalHeaders($server);
        $ipAddress = is_string($server['REMOTE_ADDR'] ?? null)
            ? $server['REMOTE_ADDR']
            : '';
        $userAgent = $this->header($headers, 'user-agent')
            ?? (is_string($server['HTTP_USER_AGENT'] ?? null) ? $server['HTTP_USER_AGENT'] : '');
        $request = $this->requestFromServer($server, $headers);

        return $this->identify($ipAddress, $userAgent, $request, $now);
    }

    public function identify(
        string $ipAddress,
        string $userAgent = '',
        ?WebBotAuthRequest $request = null,
        ?int $now = null,
    ): ?AutomaticBotVerification {
        if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        if ($this->webBotAuth !== null && $request !== null) {
            $verified = $this->webBotAuth->identify($request, $now);

            if ($verified !== null) {
                return new AutomaticBotVerification(
                    AutomaticBotVerification::WEB_BOT_AUTH,
                    $verified,
                    $ipAddress,
                );
            }
        }

        if ($this->ipRanges !== null && $userAgent !== '') {
            $verified = $this->ipRanges->identify($ipAddress, $userAgent);

            if ($verified !== null) {
                return new AutomaticBotVerification(
                    AutomaticBotVerification::IP_RANGE,
                    $verified,
                    $ipAddress,
                );
            }
        }

        if ($this->dns !== null) {
            $verified = $this->dns->identify($ipAddress);

            if ($verified !== null) {
                return new AutomaticBotVerification(
                    AutomaticBotVerification::DNS,
                    $verified,
                    $ipAddress,
                );
            }
        }

        return null;
    }

    public function classify(
        string $ipAddress,
        string $userAgent = '',
        ?WebBotAuthRequest $request = null,
        ?int $now = null,
    ): BotVerificationStatus {
        if ($this->identify($ipAddress, $userAgent, $request, $now) !== null) {
            return BotVerificationStatus::VERIFIED;
        }

        return $this->claimsBotIdentity($userAgent, $request)
            ? BotVerificationStatus::SPOOFED
            : BotVerificationStatus::UNKNOWN;
    }

    /**
     * @param array<string, string|list<string>> $headers
     */
    public function classifyHttp(
        string $ipAddress,
        string $method,
        string $targetUri,
        array $headers = [],
        ?int $now = null,
    ): BotVerificationStatus {
        $request = new WebBotAuthRequest($method, $targetUri, $headers);

        return $this->classify(
            $ipAddress,
            $request->header('user-agent') ?? '',
            $request,
            $now,
        );
    }

    /**
     * @param null|array<string, mixed> $server
     * @param null|array<string, string|list<string>> $headers
     */
    public function classifyGlobals(
        ?array $server = null,
        ?array $headers = null,
        ?int $now = null,
    ): BotVerificationStatus {
        $server ??= $_SERVER;
        $headers ??= $this->globalHeaders($server);
        $ipAddress = is_string($server['REMOTE_ADDR'] ?? null)
            ? $server['REMOTE_ADDR']
            : '';
        $userAgent = $this->header($headers, 'user-agent')
            ?? (is_string($server['HTTP_USER_AGENT'] ?? null) ? $server['HTTP_USER_AGENT'] : '');
        $request = $this->requestFromServer($server, $headers);

        if ($this->identify($ipAddress, $userAgent, $request, $now) !== null) {
            return BotVerificationStatus::VERIFIED;
        }

        return $this->claimsBotIdentity($userAgent, $request)
            || $this->header($headers, 'signature-agent') !== null
                ? BotVerificationStatus::SPOOFED
                : BotVerificationStatus::UNKNOWN;
    }

    /**
     * @param array<string, string|list<string>> $headers
     */
    public function isVerifiedHttp(
        string $ipAddress,
        string $method,
        string $targetUri,
        array $headers = [],
        ?int $now = null,
    ): bool {
        return $this->identifyHttp($ipAddress, $method, $targetUri, $headers, $now) !== null;
    }

    /**
     * @param null|array<string, mixed> $server
     * @param null|array<string, string|list<string>> $headers
     */
    public function isVerifiedGlobals(
        ?array $server = null,
        ?array $headers = null,
        ?int $now = null,
    ): bool {
        return $this->identifyGlobals($server, $headers, $now) !== null;
    }

    public function isVerified(
        string $ipAddress,
        string $userAgent = '',
        ?WebBotAuthRequest $request = null,
        ?int $now = null,
    ): bool {
        return $this->identify($ipAddress, $userAgent, $request, $now) !== null;
    }

    /**
     * @param array<string, mixed> $server
     * @return array<string, string|list<string>>
     */
    private function globalHeaders(array $server): array
    {
        if (function_exists('getallheaders')) {
            $headers = getallheaders();

            if (is_array($headers)) {
                return array_filter(
                    $headers,
                    static fn (mixed $value): bool => is_string($value)
                        || (is_array($value) && array_filter($value, 'is_string') === $value),
                );
            }
        }

        $headers = [];

        foreach ($server as $name => $value) {
            if (!is_string($value)) {
                continue;
            }

            if (str_starts_with($name, 'HTTP_')) {
                $headers[str_replace('_', '-', substr($name, 5))] = $value;
            } elseif (in_array($name, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true)) {
                $headers[str_replace('_', '-', $name)] = $value;
            }
        }

        return $headers;
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, string|list<string>> $headers
     */
    private function requestFromServer(array $server, array $headers): ?WebBotAuthRequest
    {
        $method = $server['REQUEST_METHOD'] ?? null;
        $host = $server['HTTP_HOST'] ?? null;
        $requestUri = $server['REQUEST_URI'] ?? null;

        if (!is_string($method)
            || !is_string($host)
            || !is_string($requestUri)
            || !str_starts_with($requestUri, '/')
        ) {
            return null;
        }

        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        $scheme = ($https !== '' && $https !== 'off')
            || (string) ($server['SERVER_PORT'] ?? '') === '443'
                ? 'https'
                : 'http';

        try {
            return new WebBotAuthRequest(
                $method,
                $scheme.'://'.$host.$requestUri,
                $headers,
            );
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /**
     * @param array<string, string|list<string>> $headers
     */
    private function header(array $headers, string $wanted): ?string
    {
        foreach ($headers as $name => $value) {
            if (strtolower($name) === $wanted) {
                return is_array($value) ? implode(', ', $value) : $value;
            }
        }

        return null;
    }

    private function claimsBotIdentity(
        string $userAgent,
        ?WebBotAuthRequest $request,
    ): bool {
        if ($request?->header('signature-agent') !== null) {
            return true;
        }

        foreach ($this->botUserAgentClaims as $claim) {
            if (stripos($userAgent, $claim) !== false) {
                return true;
            }
        }

        return false;
    }
}
