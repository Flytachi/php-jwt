<?php

declare(strict_types=1);

namespace Flytachi\Jwt\Entity;

use OpenSSLAsymmetricKey;

/**
 * Represents a private key used for signing.
 */
final class PrivateKey
{
    private string $algorithm;
    private OpenSSLAsymmetricKey|string $keyMaterial;
    private ?string $keyId;

    public function __construct(OpenSSLAsymmetricKey|string $keyMaterial, string $algorithm, ?string $keyId = null)
    {
        $this->algorithm = $algorithm;
        $this->keyMaterial = $keyMaterial;
        $this->keyId = $keyId;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function getKeyMaterial(): OpenSSLAsymmetricKey|string
    {
        return $this->keyMaterial;
    }

    public function getKeyId(): ?string
    {
        return $this->keyId;
    }
}
