<?php

declare(strict_types=1);

namespace VerifiedBots;

use InvalidArgumentException;

final readonly class BotDefinition
{
    /**
     * @param non-empty-string $name
     * @param non-empty-list<non-empty-string> $hostnameSuffixes
     */
    public function __construct(
        public string $name,
        public array $hostnameSuffixes,
    ) {
        if (trim($name) === '') {
            throw new InvalidArgumentException('The bot name cannot be empty.');
        }

        if ($hostnameSuffixes === []) {
            throw new InvalidArgumentException('At least one hostname suffix is required.');
        }

        foreach ($hostnameSuffixes as $suffix) {
            if ($suffix === '' || filter_var($suffix, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
                throw new InvalidArgumentException(sprintf('Invalid hostname suffix: "%s".', $suffix));
            }
        }
    }

    public function matches(string $hostname): bool
    {
        $hostname = strtolower(rtrim($hostname, '.'));

        foreach ($this->hostnameSuffixes as $suffix) {
            $suffix = strtolower(rtrim($suffix, '.'));

            if ($hostname === $suffix || str_ends_with($hostname, '.'.$suffix)) {
                return true;
            }
        }

        return false;
    }
}
