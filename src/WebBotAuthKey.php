<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;

final readonly class WebBotAuthKey
{
    public string $publicKey;
    public string $id;

    public function __construct(
        public string $x,
        public ?int $notBefore = null,
        public ?int $expiresAt = null,
    ) {
        $publicKey = self::base64UrlDecode($x);

        if ($publicKey === null || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidArgumentException('The Ed25519 JWK "x" value is invalid.');
        }

        $this->publicKey = $publicKey;
        $this->id = self::thumbprint($x);

        if ($notBefore !== null && $expiresAt !== null && $expiresAt < $notBefore) {
            throw new InvalidArgumentException('The JWK validity window is invalid.');
        }
    }

    /**
     * @param array<string, mixed> $jwk
     */
    public static function fromJwk(array $jwk): self
    {
        if (($jwk['kty'] ?? null) !== 'OKP'
            || ($jwk['crv'] ?? null) !== 'Ed25519'
            || !is_string($jwk['x'] ?? null)
        ) {
            throw new InvalidArgumentException('Only Ed25519 public JWKs are supported.');
        }

        $thumbprint = self::thumbprint($jwk['x']);

        if (isset($jwk['kid']) && (!is_string($jwk['kid']) || !hash_equals($thumbprint, $jwk['kid']))) {
            throw new InvalidArgumentException('The JWK "kid" must equal its RFC 7638 thumbprint.');
        }

        foreach (['nbf', 'exp'] as $parameter) {
            if (isset($jwk[$parameter]) && !is_int($jwk[$parameter])) {
                throw new InvalidArgumentException(sprintf('The JWK "%s" value must be an integer.', $parameter));
            }
        }

        return new self($jwk['x'], $jwk['nbf'] ?? null, $jwk['exp'] ?? null);
    }

    private static function thumbprint(string $x): string
    {
        $json = sprintf('{"crv":"Ed25519","kty":"OKP","x":"%s"}', $x);

        return rtrim(strtr(base64_encode(hash('sha256', $json, true)), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $value): ?string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1) {
            return null;
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
