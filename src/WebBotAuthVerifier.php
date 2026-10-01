<?php

declare(strict_types=1);

namespace VerifiedBots;

final readonly class WebBotAuthVerifier
{
    public const MAX_VALIDITY_SECONDS = 86400;
    public const CLOCK_SKEW_SECONDS = 30;

    public function __construct(
        private WebBotAuthKeyStore $keys,
        private int $maximumValidity = self::MAX_VALIDITY_SECONDS,
        private int $clockSkew = self::CLOCK_SKEW_SECONDS,
    ) {}

    public function isVerified(WebBotAuthRequest $request, ?int $now = null): bool
    {
        return $this->identify($request, $now) !== null;
    }

    public function identify(WebBotAuthRequest $request, ?int $now = null): ?VerifiedWebBot
    {
        if ($request->component('@scheme') !== 'https') {
            return null;
        }

        $signatureInput = $request->header('signature-input');
        $signature = $request->header('signature');
        $signatureAgent = $request->header('signature-agent');

        if ($signatureInput === null || $signature === null || $signatureAgent === null) {
            return null;
        }

        $inputs = $this->splitDictionary($signatureInput);
        $signatures = $this->parseSignatures($signature);
        $agents = $this->parseAgents($signatureAgent);

        if ($inputs === null || $signatures === null || $agents === null) {
            return null;
        }

        $inputLabels = array_keys($inputs);
        $signatureLabels = array_keys($signatures);
        sort($inputLabels);
        sort($signatureLabels);

        if ($inputLabels !== $signatureLabels) {
            return null;
        }

        foreach ($inputs as $label => $rawInput) {
            $parsed = $this->parseSignatureInput($rawInput);

            if ($parsed === null) {
                return null;
            }

            if (($parsed['params']['tag'] ?? null) !== 'web-bot-auth'
                || ($parsed['params']['alg'] ?? null) !== 'ed25519'
                || !is_int($parsed['params']['created'] ?? null)
                || !is_int($parsed['params']['expires'] ?? null)
                || !is_string($parsed['params']['keyid'] ?? null)
            ) {
                continue;
            }

            $created = $parsed['params']['created'];
            $expires = $parsed['params']['expires'];
            $now ??= time();

            if ($expires < $created
                || $expires - $created > $this->maximumValidity
                || $created > $now + $this->clockSkew
                || $expires < $now - $this->clockSkew
            ) {
                continue;
            }

            $coveredNames = array_column($parsed['components'], 'name');

            if (!in_array('@authority', $coveredNames, true)
                && !in_array('@target-uri', $coveredNames, true)
            ) {
                continue;
            }

            $agent = $this->coveredAgent($label, $parsed['components'], $agents);

            if ($agent === null || parse_url($agent['uri'], PHP_URL_SCHEME) !== 'https') {
                continue;
            }

            $key = $this->keys->find($agent['uri'], $agent['type'], $parsed['params']['keyid']);
            $base = $this->signatureBase($request, $parsed['components'], $rawInput, $agents);

            if ($key !== null
                && ($key->notBefore === null || $key->notBefore <= $now + $this->clockSkew)
                && ($key->expiresAt === null || $key->expiresAt >= $now - $this->clockSkew)
                && $base !== null
                && sodium_crypto_sign_verify_detached($signatures[$label], $base, $key->publicKey)
            ) {
                return new VerifiedWebBot($agent['uri'], $key->id, $label);
            }
        }

        return null;
    }

    /**
     * @param list<array{name: string, serialized: string, params: array<string, int|string>}> $components
     * @param array<string, array{uri: string, type: string, serialized: string}> $agents
     */
    private function signatureBase(
        WebBotAuthRequest $request,
        array $components,
        string $rawInput,
        array $agents,
    ): ?string {
        $lines = [];

        foreach ($components as $component) {
            $value = null;

            if ($component['name'] === 'signature-agent') {
                $member = $component['params']['key'] ?? null;
                $value = is_string($member) ? ($agents[$member]['serialized'] ?? null) : null;
            } elseif ($component['params'] === []) {
                $value = $request->component($component['name']);
            }

            if ($value === null || str_contains($value, "\n") || str_contains($value, "\r")) {
                return null;
            }

            $lines[] = $component['serialized'].': '.$value;
        }

        $lines[] = '"@signature-params": '.$rawInput;

        return implode("\n", $lines);
    }

    /**
     * @param list<array{name: string, serialized: string, params: array<string, int|string>}> $components
     * @param array<string, array{uri: string, type: string, serialized: string}> $agents
     * @return array{uri: string, type: string, serialized: string}|null
     */
    private function coveredAgent(string $label, array $components, array $agents): ?array
    {
        foreach ($components as $component) {
            if ($component['name'] !== 'signature-agent') {
                continue;
            }

            $member = $component['params']['key'] ?? null;

            if (is_string($member) && isset($agents[$member]) && ($member === $label || !isset($agents[$label]))) {
                return $agents[$member];
            }
        }

        return null;
    }

    /**
     * @return array{
     *   components: list<array{name: string, serialized: string, params: array<string, int|string>}>,
     *   params: array<string, int|string>
     * }|null
     */
    private function parseSignatureInput(string $input): ?array
    {
        if (preg_match('/^(\((?:[^"\\\\]|"(?:[^"\\\\]|\\\\.)*")*\))((?:;[a-z][a-z0-9_.*-]*(?:=(?:"(?:[^"\\\\]|\\\\.)*"|-?[0-9]+|[a-zA-Z*][a-zA-Z0-9_.*:\/-]*))?)*)$/D', $input, $matches) !== 1) {
            return null;
        }

        $inside = substr($matches[1], 1, -1);
        $components = [];
        $offset = 0;

        while ($offset < strlen($inside)) {
            while (($inside[$offset] ?? null) === ' ') {
                $offset++;
            }

            if (preg_match('/\G"([a-z0-9@_-]+)"((?:;[a-z][a-z0-9_.*-]*=(?:"(?:[^"\\\\]|\\\\.)*"|-?[0-9]+|[a-zA-Z*][a-zA-Z0-9_.*:\/-]*))*)/A', substr($inside, $offset), $part) !== 1) {
                return null;
            }

            $serialized = '"'.$part[1].'"'.$part[2];
            $params = $this->parseParameters($part[2]);

            if ($params === null) {
                return null;
            }

            $components[] = ['name' => $part[1], 'serialized' => $serialized, 'params' => $params];
            $offset += strlen($part[0]);
        }

        if ($components === []) {
            return null;
        }

        $params = $this->parseParameters($matches[2]);

        return $params === null ? null : ['components' => $components, 'params' => $params];
    }

    /**
     * @return array<string, int|string>|null
     */
    private function parseParameters(string $input): ?array
    {
        $params = [];
        $offset = 0;

        while ($offset < strlen($input)) {
            if (preg_match('/\G;([a-z][a-z0-9_.*-]*)(?:=("(?:[^"\\\\]|\\\\.)*"|-?[0-9]+|[a-zA-Z*][a-zA-Z0-9_.*:\/-]*))?/', $input, $match, 0, $offset) !== 1) {
                return null;
            }

            if (array_key_exists($match[1], $params) || !isset($match[2])) {
                return null;
            }

            $raw = $match[2];
            $value = $raw[0] === '"' ? $this->decodeString($raw) : null;

            if ($raw[0] === '"' && $value === null) {
                return null;
            }

            $params[$match[1]] = $value
                ?? (preg_match('/^-?[0-9]+$/D', $raw) === 1 ? (int) $raw : $raw);
            $offset += strlen($match[0]);
        }

        return $params;
    }

    /**
     * @return array<string, string>|null
     */
    private function splitDictionary(string $input): ?array
    {
        $members = $this->splitTopLevel($input);
        $result = [];

        foreach ($members as $member) {
            if (preg_match('/^([a-z*][a-z0-9_.*-]*)=(.+)$/D', trim($member), $match) !== 1
                || isset($result[$match[1]])
            ) {
                return null;
            }

            $result[$match[1]] = $match[2];
        }

        return $result === [] ? null : $result;
    }

    /**
     * @return array<string, string>|null
     */
    private function parseSignatures(string $input): ?array
    {
        $members = $this->splitDictionary($input);

        if ($members === null) {
            return null;
        }

        $result = [];

        foreach ($members as $label => $value) {
            if (preg_match('/^:([A-Za-z0-9+\/]*={0,2}):$/D', $value, $match) !== 1) {
                return null;
            }

            $decoded = base64_decode($match[1], true);

            if ($decoded === false || strlen($decoded) !== SODIUM_CRYPTO_SIGN_BYTES) {
                return null;
            }

            $result[$label] = $decoded;
        }

        return $result;
    }

    /**
     * @return array<string, array{uri: string, type: string, serialized: string}>|null
     */
    private function parseAgents(string $input): ?array
    {
        $members = $this->splitDictionary($input);

        if ($members === null) {
            return null;
        }

        $result = [];

        foreach ($members as $label => $value) {
            if (preg_match('/^"((?:[^"\\\\]|\\\\.)*)"(?:;type=([a-z][a-z0-9_-]*))?$/D', $value, $match) !== 1) {
                return null;
            }

            $uri = $this->decodeString('"'.$match[1].'"');
            $type = $match[2] ?? 'directory';

            if ($uri === null || filter_var($uri, FILTER_VALIDATE_URL) === false) {
                return null;
            }

            $result[$label] = ['uri' => $uri, 'type' => $type, 'serialized' => $value];
        }

        return $result;
    }

    private function decodeString(string $value): ?string
    {
        $inner = substr($value, 1, -1);

        if (preg_match('/\\\\(?!["\\\\])/', $inner) === 1) {
            return null;
        }

        return str_replace(['\\"', '\\\\'], ['"', '\\'], $inner);
    }

    /**
     * @return list<string>
     */
    private function splitTopLevel(string $input): array
    {
        $parts = [];
        $start = 0;
        $quoted = false;
        $bytes = false;
        $depth = 0;

        for ($index = 0, $length = strlen($input); $index < $length; $index++) {
            $char = $input[$index];

            if ($quoted && $char === '\\') {
                $index++;
                continue;
            }

            if (!$bytes && $char === '"') {
                $quoted = !$quoted;
            } elseif (!$quoted && $char === ':') {
                $bytes = !$bytes;
            } elseif (!$quoted && !$bytes && $char === '(') {
                $depth++;
            } elseif (!$quoted && !$bytes && $char === ')') {
                $depth--;
            } elseif (!$quoted && !$bytes && $depth === 0 && $char === ',') {
                $parts[] = substr($input, $start, $index - $start);
                $start = $index + 1;
            }
        }

        if ($quoted || $bytes || $depth !== 0) {
            return [];
        }

        $parts[] = substr($input, $start);

        return $parts;
    }
}
