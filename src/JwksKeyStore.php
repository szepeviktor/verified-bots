<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;

/**
 * A preloaded, SSRF-safe key store. Applications can refresh the JWKS documents
 * out of band, or implement WebBotAuthKeyStore for controlled dynamic discovery.
 */
final class JwksKeyStore implements WebBotAuthKeyStore
{
    /** @var array<string, array<string, WebBotAuthKey>> */
    private array $keys = [];

    /**
     * @param array<string, array<string, mixed>|string> $documents Signature-Agent URI => JWKS
     */
    public function __construct(array $documents)
    {
        foreach ($documents as $signatureAgent => $document) {
            if (!is_string($signatureAgent) || $signatureAgent === '') {
                throw new InvalidArgumentException('A Signature-Agent URI cannot be empty.');
            }

            if (is_string($document)) {
                $document = json_decode($document, true, flags: JSON_THROW_ON_ERROR);
            }

            if (!is_array($document) || !is_array($document['keys'] ?? null)) {
                throw new InvalidArgumentException('Each key document must be a JWKS object.');
            }

            if (count($document['keys']) > 32) {
                throw new InvalidArgumentException('A JWKS document cannot contain more than 32 keys.');
            }

            foreach ($document['keys'] as $jwk) {
                if (!is_array($jwk)) {
                    throw new InvalidArgumentException('Each JWKS key must be an object.');
                }

                $key = WebBotAuthKey::fromJwk($jwk);
                $this->keys[$signatureAgent][$key->id] = $key;
            }
        }
    }

    public function find(string $signatureAgent, string $discoveryType, string $keyId): ?WebBotAuthKey
    {
        if (!in_array($discoveryType, ['directory', 'jwks_uri'], true)) {
            return null;
        }

        return $this->keys[$signatureAgent][$keyId] ?? null;
    }
}
