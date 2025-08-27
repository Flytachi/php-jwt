<?php

declare(strict_types=1);

namespace Flytachi\Jwt\Entity;

/**
 * Represents the header of a JWT.
 */
final class JwtHeader
{
    public string $algorithm;
    public string $type = 'JWT';
    public ?string $keyId;
    /** @var array<string, mixed> */
    public array $extra;

    public function __construct(string $algorithm, ?string $keyId = null, array $extra = [])
    {
        $this->algorithm = $algorithm;
        $this->keyId = $keyId;
        $this->extra = $extra;
    }

    public function toArray(): array
    {
        $headerData = array_merge($this->extra, [
            'alg' => $this->algorithm,
            'typ' => $this->type,
        ]);

        if ($this->keyId !== null) {
            $headerData['kid'] = $this->keyId;
        }
        return $headerData;
    }
}
