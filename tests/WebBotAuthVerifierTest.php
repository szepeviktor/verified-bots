<?php

declare(strict_types=1);

namespace VerifiedBots\Tests;

use PHPUnit\Framework\TestCase;
use VerifiedBots\JwksKeyStore;
use VerifiedBots\WebBotAuthKey;
use VerifiedBots\WebBotAuthRequest;
use VerifiedBots\WebBotAuthVerifier;

final class WebBotAuthVerifierTest extends TestCase
{
    private const NOW = 1785758400;
    private const AGENT = 'https://crawler.example';

    public function testItVerifiesAnEd25519WebBotAuthRequest(): void
    {
        [$request, $key] = $this->signedRequest();
        $verifier = new WebBotAuthVerifier($this->keyStore($key));

        $bot = $verifier->identify($request, self::NOW);

        self::assertNotNull($bot);
        self::assertSame(self::AGENT, $bot->signatureAgent);
        self::assertSame($key->id, $bot->keyId);
        self::assertSame('sig1', $bot->signatureLabel);
    }

    public function testItVerifiesTheIetfDraftEd25519TestVector(): void
    {
        $keyId = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
        $input = '("@authority" "signature-agent";key="agent2")'
            .';created=1735689600'
            .';keyid="'.$keyId.'"'
            .';alg="ed25519"'
            .';expires=4889289600'
            .';nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="'
            .';tag="web-bot-auth"';
        $request = new WebBotAuthRequest('GET', 'https://example.com/', [
            'Signature-Agent' => 'agent2="https://signature-agent.test"',
            'Signature-Input' => 'sig2='.$input,
            'Signature' => 'sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:',
        ]);
        $keys = new JwksKeyStore([
            'https://signature-agent.test' => [
                'keys' => [[
                    'kty' => 'OKP',
                    'crv' => 'Ed25519',
                    'x' => 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
                    'kid' => $keyId,
                ]],
            ],
        ]);
        $verifier = new WebBotAuthVerifier($keys, maximumValidity: 3153600000);

        self::assertTrue($verifier->isVerified($request, 1735689600));
    }

    public function testItRejectsARequestWhoseSignedTargetWasChanged(): void
    {
        [$request, $key] = $this->signedRequest();
        $request = new WebBotAuthRequest('GET', 'https://example.com/private', [
            'Signature-Agent' => $request->header('signature-agent'),
            'Signature-Input' => $request->header('signature-input'),
            'Signature' => $request->header('signature'),
        ]);

        self::assertFalse((new WebBotAuthVerifier($this->keyStore($key)))->isVerified($request, self::NOW));
    }

    public function testItOmitsTheDefaultPortFromAuthority(): void
    {
        $request = new WebBotAuthRequest('GET', 'https://EXAMPLE.com:443/articles', []);

        self::assertSame('example.com', $request->component('@authority'));
        self::assertSame('https://example.com/articles', $request->component('@target-uri'));
    }

    public function testItRejectsSignaturesReceivedOverPlainHttp(): void
    {
        [$request, $key] = $this->signedRequest();
        $request = new WebBotAuthRequest('GET', 'http://example.com/articles', [
            'Signature-Agent' => $request->header('signature-agent'),
            'Signature-Input' => $request->header('signature-input'),
            'Signature' => $request->header('signature'),
        ]);

        self::assertFalse((new WebBotAuthVerifier($this->keyStore($key)))->isVerified($request, self::NOW));
    }

    public function testItRejectsExpiredAndExcessivelyLongLivedSignatures(): void
    {
        [$expired, $expiredKey] = $this->signedRequest(created: self::NOW - 120, expires: self::NOW - 60);
        [$longLived, $longLivedKey] = $this->signedRequest(
            created: self::NOW,
            expires: self::NOW + WebBotAuthVerifier::MAX_VALIDITY_SECONDS + 1,
        );

        self::assertFalse(
            (new WebBotAuthVerifier($this->keyStore($expiredKey)))->isVerified($expired, self::NOW),
        );
        self::assertFalse(
            (new WebBotAuthVerifier($this->keyStore($longLivedKey)))->isVerified($longLived, self::NOW),
        );
    }

    public function testItRequiresTheSignatureAgentMemberToBeSigned(): void
    {
        [$request, $key] = $this->signedRequest(components: ['@authority']);

        self::assertFalse((new WebBotAuthVerifier($this->keyStore($key)))->isVerified($request, self::NOW));
    }

    public function testItRejectsAnUnknownKey(): void
    {
        [$request] = $this->signedRequest();
        $otherKey = $this->newKey()[1];

        self::assertFalse((new WebBotAuthVerifier($this->keyStore($otherKey)))->isVerified($request, self::NOW));
    }

    public function testJwksKidMustBeTheRfc7638Thumbprint(): void
    {
        [, $key] = $this->newKey();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('thumbprint');

        new JwksKeyStore([
            self::AGENT => [
                'keys' => [[
                    'kty' => 'OKP',
                    'crv' => 'Ed25519',
                    'x' => $key->x,
                    'kid' => 'not-the-thumbprint',
                ]],
            ],
        ]);
    }

    /**
     * @param list<string> $components
     * @return array{WebBotAuthRequest, WebBotAuthKey}
     */
    private function signedRequest(
        int $created = self::NOW - 10,
        int $expires = self::NOW + 50,
        array $components = ['@method', '@authority', '@path', 'signature-agent'],
    ): array {
        [$secretKey, $key] = $this->newKey();
        $serializedComponents = [];
        $baseLines = [];

        foreach ($components as $component) {
            if ($component === 'signature-agent') {
                $serializedComponents[] = '"signature-agent";key="sig1"';
                $baseLines[] = '"signature-agent";key="sig1": "'.self::AGENT.'"';
                continue;
            }

            $serializedComponents[] = '"'.$component.'"';
            $baseLines[] = match ($component) {
                '@method' => '"@method": GET',
                '@authority' => '"@authority": example.com',
                '@path' => '"@path": /articles',
                default => throw new \LogicException('Unsupported test component.'),
            };
        }

        $input = '('.implode(' ', $serializedComponents).')'
            .';created='.$created
            .';keyid="'.$key->id.'"'
            .';alg="ed25519"'
            .';expires='.$expires
            .';nonce="unique-test-nonce"'
            .';tag="web-bot-auth"';
        $baseLines[] = '"@signature-params": '.$input;
        $signature = sodium_crypto_sign_detached(implode("\n", $baseLines), $secretKey);

        return [
            new WebBotAuthRequest('GET', 'https://example.com/articles', [
                'Signature-Agent' => 'sig1="'.self::AGENT.'"',
                'Signature-Input' => 'sig1='.$input,
                'Signature' => 'sig1=:'.base64_encode($signature).':',
            ]),
            $key,
        ];
    }

    /**
     * @return array{string, WebBotAuthKey}
     */
    private function newKey(): array
    {
        $pair = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($pair);
        $x = rtrim(strtr(base64_encode(sodium_crypto_sign_publickey($pair)), '+/', '-_'), '=');

        return [$secretKey, new WebBotAuthKey($x)];
    }

    private function keyStore(WebBotAuthKey $key): JwksKeyStore
    {
        return new JwksKeyStore([
            self::AGENT => [
                'keys' => [[
                    'kty' => 'OKP',
                    'crv' => 'Ed25519',
                    'x' => $key->x,
                    'kid' => $key->id,
                ]],
            ],
        ]);
    }
}
