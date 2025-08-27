<?php

declare(strict_types=1);

namespace Flytachi\Jwt\Entity;

/**
 * Represents the payload of a JWT.
 */
final class JwtPayload
{
    /** @var array<string, mixed> */
    private array $claims;

    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    /**
     * @param string $name The name of the claim.
     * @param mixed|null $default The default value to return if the claim doesn't exist.
     * @return mixed
     */
    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    public function toArray(): array
    {
        return $this->claims;
    }
}
