<?php

declare(strict_types=1);

namespace VerifiedBots;

use JsonException;
use UnexpectedValueException;

final class JsonIpRangeBotDefinitionLoader
{
    /**
     * @return non-empty-list<IpRangeBotDefinition>
     */
    public static function defaults(): array
    {
        return self::fromDirectory(dirname(__DIR__).'/resources/ip-ranges');
    }

    /**
     * @return non-empty-list<IpRangeBotDefinition>
     */
    public static function fromDirectory(string $directory): array
    {
        $paths = glob(rtrim($directory, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'*.json');

        if ($paths === false || $paths === []) {
            throw new UnexpectedValueException('No IP range bot definition JSON files were found.');
        }

        sort($paths, SORT_STRING);
        $definitions = [];

        foreach ($paths as $path) {
            $definitions[] = self::fromFile($path);
        }

        return $definitions;
    }

    public static function fromFile(string $path): IpRangeBotDefinition
    {
        $json = file_get_contents($path);

        if ($json === false) {
            throw new UnexpectedValueException(sprintf('Cannot read bot definition: %s', $path));
        }

        try {
            $document = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new UnexpectedValueException(
                sprintf('Invalid JSON in bot definition %s: %s', $path, $exception->getMessage()),
                previous: $exception,
            );
        }

        if (!is_array($document)
            || !is_string($document['name'] ?? null)
            || !is_array($document['userAgentSubstrings'] ?? null)
            || !is_string($document['sourceUrl'] ?? null)
        ) {
            throw new UnexpectedValueException(sprintf('Invalid bot definition schema: %s', $path));
        }

        $substrings = [];

        foreach ($document['userAgentSubstrings'] as $substring) {
            if (!is_string($substring)) {
                throw new UnexpectedValueException(sprintf('Invalid User-Agent substring in %s', $path));
            }

            $substrings[] = $substring;
        }

        return new IpRangeBotDefinition(
            $document['name'],
            $substrings,
            $document['sourceUrl'],
        );
    }
}
