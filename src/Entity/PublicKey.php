<?php

declare(strict_types=1);

namespace Flytachi\Jwt\Entity;

use OpenSSLAsymmetricKey;

/**
 * Represents a public key used for verification.
 * It encapsulates the key material and the algorithm it's meant to be used with.
 */
final class PublicKey
{
    private string $algorithm;
    private OpenSSLAsymmetricKey|string $keyMaterial;

    public function __construct(OpenSSLAsymmetricKey|string $keyMaterial, string $algorithm = 'HS256')
    {
        $this->algorithm = $algorithm;
        $this->keyMaterial = $keyMaterial;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function getKeyMaterial(): OpenSSLAsymmetricKey|string
    {
        return $this->keyMaterial;
    }
}
