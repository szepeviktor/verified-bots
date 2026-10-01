# Verified Bots

A small PHP package for identifying genuine web crawlers. It supports official
IP/CIDR feeds, provider DNS verification, and cryptographic
[Web Bot Auth](https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-httpsig-protocol)
request signatures.

DNS verification follows the providers' forward-confirmed reverse DNS process:

1. Reverse-resolve the request IP.
2. Require a provider-owned hostname suffix.
3. Forward-resolve that hostname and require the original IP.
4. Cache both successful and unsuccessful results for one week.

Checking a user-agent alone is not verification because it can be spoofed.

## Automatic verification

Use one entry point to try every applicable method automatically. The order is
Web Bot Auth, official IP/CIDR ranges, then forward-confirmed reverse DNS:

```php
use VerifiedBots\AutomaticBotVerifier;

$verifier = new AutomaticBotVerifier($cache);
$result = $verifier->identifyHttp(
    ipAddress: $_SERVER['REMOTE_ADDR'],
    method: $_SERVER['REQUEST_METHOD'],
    targetUri: 'https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
    headers: getallheaders(),
);

if ($result !== null) {
    printf("Verified %s using %s\n", $result->name, $result->method);
}
```

`targetUri` csak a Web Bot Authhoz kell: az aláírást a konkrét HTTPS
hosthoz, útvonalhoz és queryhez köti, ezért nem másolható át másik URL-re.
Reverse proxy mögött a bot által látott nyilvános URL-t add át. Ha csak
IP/CIDR- és DNS-ellenőrzés kell, használd az `identify()` metódust; ahhoz nem
kell `targetUri`.

Hagyományos PHP-környezetben paraméterek nélkül is használható:

```php
$result = $verifier->identifyGlobals();
```

Ez a `$_SERVER` és `getallheaders()` értékeit olvassa. Reverse proxy mögött
inkább az explicit `identifyHttp()` ajánlott, hogy biztosan a nyilvános URL és
a valódi kliens-IP kerüljön ellenőrzésre.

Only the PSR-16 cache is required. Every verifier can still be replaced, and
each method can be disabled with named constructor parameters:

```php
$verifier = new AutomaticBotVerifier(
    cache: $cache,
    ipRanges: $customIpRangeVerifier,
    dns: $customDnsVerifier,
    webBotAuth: $customWebBotAuthVerifier,
    enableDns: false,
);
```

`identify()` is also available when the IP address, User-Agent, and optional
`WebBotAuthRequest` have already been extracted by the application or framework.

For policy decisions, the parallel `classify()`, `classifyHttp()`, and
`classifyGlobals()` methods return a `BotVerificationStatus` enum:

```php
use VerifiedBots\BotVerificationStatus;

$status = $verifier->classifyGlobals();

if ($status === BotVerificationStatus::SPOOFED) {
    // A known bot identity was claimed but could not be verified.
}
```

The cases are `VERIFIED`, `SPOOFED`, and `UNKNOWN`. Classification is
fail-closed: an unverified known User-Agent or `Signature-Agent` claim is
`SPOOFED`, including when its network-based verification is temporarily
unavailable. Custom User-Agent claim substrings can be passed with the
`botUserAgentClaims` constructor parameter.

## IP/CIDR verification

`IpRangeBotVerifier` first matches the request's User-Agent to a bot definition,
then requires the request IP to belong to a CIDR published in that provider's
official JSON feed:

```php
use VerifiedBots\IpRangeBotVerifier;

$verifier = new IpRangeBotVerifier($cache);
$bot = $verifier->identify(
    $_SERVER['REMOTE_ADDR'],
    $_SERVER['HTTP_USER_AGENT'] ?? '',
);

if ($bot !== null) {
    printf(
        "Verified %s at %s via %s\n",
        $bot->name,
        $bot->ipAddress,
        $bot->matchedCidr,
    );
}
```

Bundled JSON definitions configure Googlebot, Bingbot, and Applebot. They point
to the providers' live JSON feeds; CIDRs are not hard-coded into PHP. A feed is
downloaded only after its User-Agent matches, then cached according to
`Cache-Control: max-age` (one-hour fallback, 24-hour maximum). Failed downloads
are cached for 60 seconds.

Feed fetching permits HTTPS on port 443 only, rejects private and reserved
destinations, pins cURL to the validated IP against DNS rebinding, refuses
redirects, and limits both response size and prefix count.

Custom definitions use the same `.json` structure as files under
`resources/ip-ranges`:

```json
{
    "name": "ExampleBot",
    "userAgentSubstrings": ["ExampleBot"],
    "sourceUrl": "https://crawler.example/ip-ranges.json"
}
```

Load a directory with
`JsonIpRangeBotDefinitionLoader::fromDirectory('/path/to/definitions')` and pass
the result as the verifier's third constructor argument. Feed documents use the
Google/Bing/Apple shape: a `prefixes` array containing `ipv4Prefix` or
`ipv6Prefix`.

## Installation

```bash
composer require verified-bots/verified-bots
```

Pass any [PSR-16](https://www.php-fig.org/psr/psr-16/) cache implementation:

```php
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;
use VerifiedBots\BotVerifier;

$cache = new Psr16Cache(new FilesystemAdapter(namespace: 'verified-bots'));
$verifier = new BotVerifier($cache);

$bot = $verifier->identify($_SERVER['REMOTE_ADDR']);

if ($bot !== null) {
    printf(
        "Verified %s at %s (%s)\n",
        $bot->name,
        $bot->ipAddress,
        $bot->hostname,
    );
}

$isVerified = $verifier->isVerified($_SERVER['REMOTE_ADDR']);
```

## Web Bot Auth

Web Bot Auth signs HTTP requests using RFC 9421. The verifier currently accepts
the Ed25519 profile from the active IETF draft, including:

- `Signature`, `Signature-Input`, and the current dictionary-form
  `Signature-Agent` fields;
- RFC 7638 JWK thumbprints as `keyid`;
- `@authority` or `@target-uri` binding;
- mandatory `created`, `expires`, and `tag="web-bot-auth"` parameters;
- a maximum 24-hour validity window and 30 seconds of clock skew.

For automatic first-visit discovery, provide a PSR-16 cache:

```php
use VerifiedBots\RemoteJwksKeyStore;
use VerifiedBots\WebBotAuthRequest;
use VerifiedBots\WebBotAuthVerifier;

$keys = new RemoteJwksKeyStore($cache);

$request = new WebBotAuthRequest(
    method: $_SERVER['REQUEST_METHOD'],
    targetUri: 'https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
    headers: [
        'Signature-Agent' => $_SERVER['HTTP_SIGNATURE_AGENT'] ?? '',
        'Signature-Input' => $_SERVER['HTTP_SIGNATURE_INPUT'] ?? '',
        'Signature' => $_SERVER['HTTP_SIGNATURE'] ?? '',
    ],
);

$bot = (new WebBotAuthVerifier($keys))->identify($request);

if ($bot !== null) {
    printf("Verified signed agent %s\n", $bot->signatureAgent);
}
```

On the first request from a previously unseen agent, `RemoteJwksKeyStore`:

1. reads the signed `Signature-Agent` member;
2. resolves a `directory` value to
   `/.well-known/http-message-signatures-directory`, or uses a `jwks_uri`
   value directly;
3. permits HTTPS on port 443 only, rejects private and reserved destination
   addresses, and pins cURL to the validated public IP to prevent DNS rebinding;
4. downloads at most 256 KiB with a five-second timeout and no redirects;
5. validates at most 32 Ed25519 keys and caches the JWKS;
6. verifies the request signature.

The successful cache TTL follows the directory response's
`Cache-Control: max-age`, with a one-hour fallback and a 24-hour local maximum.
The optional `cacheTtl` constructor argument can impose a
shorter application limit. Failed discovery is cached for 60 seconds to avoid
repeated network work.

For deployments that permit only preregistered agents, `JwksKeyStore` remains
available for loading trusted JWKS documents without network access.

The default cache TTL is `BotVerifier::CACHE_TTL` (`604800` seconds, exactly
seven days). Cache failures do not disable verification; the verifier falls
back to DNS.

## Custom bots

Replace the defaults by passing definitions as the third constructor argument:

```php
use VerifiedBots\BotDefinition;
use VerifiedBots\BotVerifier;
use VerifiedBots\NativeDnsResolver;

$verifier = new BotVerifier(
    cache: $cache,
    dns: new NativeDnsResolver(),
    definitions: [
        new BotDefinition('ExampleBot', ['crawler.example.com']),
    ],
);
```

Suffix matching is label-aware: `crawler.example.com` matches, while
`crawler.example.com.attacker.test` does not.

## Requirements

- PHP 8.2 or newer
- cURL, JSON, and Sodium PHP extensions
- A PSR-16 cache implementation
- Working reverse and forward DNS resolution

## Testing

```bash
composer install
composer test
```

## Classifying an access log

`examples/classify.php` accepts one argument containing an IP address, a tab,
and a User-Agent. It prints `IP`, status, and User-Agent as TSV:

```bash
php examples/classify.php $'66.249.66.1\tGooglebot/2.1'
```

For the usual Apache/Nginx combined log format:

```bash
sed -nE 's/^([^ ]+) .*"[^"]*" [0-9]{3} [0-9-]+ "[^"]*" "([^"]*)".*$/\1\t\2/p' access.log \
  | php examples/classify.php
```

The script streams any number of `IP<TAB>User-Agent` lines from standard input
in one process; `xargs` is neither needed nor recommended because it splits
User-Agents at whitespace. The example uses a persistent cache under
`$TMPDIR/verified-bots-cache`; override it with `VERIFIED_BOTS_CACHE_DIR`.
Only IP/CIDR and DNS verification are possible from these two log fields, so
the example explicitly disables Web Bot Auth. Historical signature verification
would additionally require the original method, full URL, signature headers,
request timestamp, and the public key valid at that time.
