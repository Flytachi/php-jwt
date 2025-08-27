<?php

declare(strict_types=1);

namespace Flytachi\Jwt;

use Flytachi\Jwt\Entity\JwtHeader;
use Flytachi\Jwt\Entity\JwtPayload;
use Flytachi\Jwt\Entity\PrivateKey;
use Flytachi\Jwt\Entity\PublicKey;
use Throwable;

/**
 * A secure, strictly-typed, and modern class for encoding and decoding JSON Web Tokens.
 * Provides static methods that operate on value objects for maximum type safety and clarity.
 */
final class JWT
{
    private const SUPPORTED_ALGORITHMS = [
        'HS256' => ['hash_hmac', 'sha256'],
        'HS384' => ['hash_hmac', 'sha384'],
        'HS512' => ['hash_hmac', 'sha512'],
        'RS256' => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384' => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512' => ['openssl', OPENSSL_ALGO_SHA512],
        'ES256' => ['openssl', OPENSSL_ALGO_SHA256],
        'ES384' => ['openssl', OPENSSL_ALGO_SHA384],
        'ES512' => ['openssl', OPENSSL_ALGO_SHA512],
    ];

    /**
     * Encodes a payload into a JWT string.
     *
     * @param JwtPayload $payload The payload to encode.
     * @param PrivateKey $privateKey The private key for signing.
     * @return string The encoded JWT.
     */
    public static function encode(JwtPayload $payload, PrivateKey $privateKey): string
    {
        $algorithm = $privateKey->getAlgorithm();
        if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            throw new JWTException("Algorithm '{$algorithm}' is not supported.");
        }

        $header = new JwtHeader($algorithm, $privateKey->getKeyId());
        $encodedHeader = self::base64UrlEncode(self::jsonEncode($header->toArray()));
        $encodedPayload = self::base64UrlEncode(self::jsonEncode($payload->toArray()));

        $dataToSign = "{$encodedHeader}.{$encodedPayload}";
        $signature = self::sign($dataToSign, $privateKey);
        $encodedSignature = self::base64UrlEncode($signature);

        return "{$dataToSign}.{$encodedSignature}";
    }

    /**
     * Decodes a JWT string, verifies it, and returns its payload.
     *
     * @param string $token The JWT string.
     * @param array<string, PublicKey> $publicKeys A map of [kid => PublicKey] for verification.
     * @param int $leeway A time allowance in seconds to account for clock skew.
     * @return JwtPayload The decoded and verified payload.
     */
    public static function decode(string $token, array $publicKeys, int $leeway = 0): JwtPayload
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                throw new JWTException('Wrong number of segments.');
            }

            [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

            $headerData = self::jsonDecode(self::base64UrlDecode($encodedHeader));
            $algorithm = $headerData['alg'] ?? 'none';
            if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
                throw new JWTException("Algorithm '{$algorithm}' is not supported.");
            }

            $keyId = $headerData['kid'] ?? null;
            $publicKey = self::findVerificationKey($algorithm, $publicKeys, $keyId);

            if ($publicKey->getAlgorithm() !== $algorithm) {
                throw new JWTException(
                    "The key's algorithm '{$publicKey->getAlgorithm()}'"
                    . " does not match the token's algorithm '{$algorithm}'."
                );
            }

            $dataToVerify = "{$encodedHeader}.{$encodedPayload}";
            $signature = self::base64UrlDecode($encodedSignature);

            if (self::isEcdsaAlgorithm($algorithm)) {
                $signature = self::signatureToDER($signature);
            }

            if (!self::verify($dataToVerify, $signature, $publicKey)) {
                throw new JWTException('Signature verification failed.');
            }

            $payloadData = self::jsonDecode(self::base64UrlDecode($encodedPayload));
            self::validateTimeClaims($payloadData, $leeway);

            return new JwtPayload($payloadData);
        } catch (Throwable $e) {
            if ($e instanceof JWTException) {
                throw $e;
            }
            throw new JWTException('Error decoding token: ' . $e->getMessage(), 0, $e);
        }
    }

    private static function sign(string $data, PrivateKey $privateKey): string
    {

        $algorithm = $privateKey->getAlgorithm();
        $keyMaterial = $privateKey->getKeyMaterial();
        [$type, $hash] = self::SUPPORTED_ALGORITHMS[$algorithm];

        switch ($type) {
            case 'openssl':
                if (!$keyMaterial instanceof \OpenSSLAsymmetricKey) {
                    throw new JWTException('OpenSSL signing requires an OpenSSLAsymmetricKey object.');
                }
                $signature = '';
                if (!openssl_sign($data, $signature, $keyMaterial, $hash)) {
                    throw new JWTException('OpenSSL signature creation failed: ' . openssl_error_string());
                }
                return $signature;

            case 'hash_hmac':
                if (!is_string($keyMaterial)) {
                    throw new JWTException('HMAC signing requires a string key.');
                }
                return hash_hmac($hash, $data, $keyMaterial, true);
        }

        throw new JWTException("Signing with type '{$type}' is not supported.");
    }

    private static function verify(string $data, string $signature, PublicKey $publicKey): bool
    {
        [$type, $hash] = self::SUPPORTED_ALGORITHMS[$publicKey->getAlgorithm()];
        $keyMaterial = $publicKey->getKeyMaterial();

        if ($type === 'openssl') {
            return openssl_verify($data, $signature, $keyMaterial, $hash) === 1;
        }
        if ($type === 'hash_hmac') {
            return hash_equals(hash_hmac($hash, $data, $keyMaterial, true), $signature);
        }
        return false;
    }

    /**
     * @param string $algorithm
     * @param array<string, PublicKey> $publicKeys
     * @param string|null $keyId
     * @return PublicKey
     */
    private static function findVerificationKey(string $algorithm, array $publicKeys, ?string $keyId): PublicKey
    {
        if (str_starts_with($algorithm, 'HS')) {
            if (empty($publicKeys)) {
                throw new JWTException('No secret key was provided for HMAC algorithm.');
            }
            return reset($publicKeys);
        }

        if ($keyId === null) {
            throw new JWTException("Token header is missing 'kid' (Key ID), required for algorithm '{$algorithm}'.");
        }
        if (!isset($publicKeys[$keyId])) {
            throw new JWTException("Key with 'kid'=\"{$keyId}\" was not found in the key set.");
        }
        return $publicKeys[$keyId];
    }

    /**
     * @param array<string, mixed> $payloadData
     */
    private static function validateTimeClaims(array $payloadData, int $leeway): void
    {
        $timestamp = time();
        if (isset($payloadData['nbf']) && $payloadData['nbf'] > ($timestamp + $leeway)) {
            throw new JWTException('Token is not yet valid (nbf).');
        }
        if (isset($payloadData['iat']) && $payloadData['iat'] > ($timestamp + $leeway)) {
            throw new JWTException('Token was issued in the future (iat).');
        }
        if (isset($payloadData['exp']) && ($timestamp - $leeway) >= $payloadData['exp']) {
            throw new JWTException('Token has expired (exp).');
        }
    }

    private static function jsonEncode(array $data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new JWTException('JSON encoding error: ' . json_last_error_msg());
        }
        return $json;
    }

    /**
     * @return array<string, mixed>
     */
    private static function jsonDecode(string $json): array
    {
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JWTException('JSON decoding error: ' . json_last_error_msg());
        }
        return $data;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    /**
     * Checks if the algorithm is ECDSA.
     */
    private static function isEcdsaAlgorithm(string $alg): bool
    {
        return str_starts_with($alg, 'ES');
    }

    /**
     * Converts a raw ECDSA signature to an ASN.1 DER sequence.
     *
     * @param string $signature The raw signature (r-value and s-value concatenated).
     * @return string The encoded DER object.
     */
    private static function signatureToDER(string $signature): string
    {
        // Separate the signature into r-value and s-value.
        $length = (int) (strlen($signature) / 2);
        if ($length === 0) {
            return '';
        }
        [$r, $s] = str_split($signature, $length);

        // r and s must be positive integers.
        // If the first byte is >= 0x80, prepend a null byte to ensure it's positive.
        if (ord($r[0]) > 0x7F) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7F) {
            $s = "\x00" . $s;
        }

        $rSequence = "\x02" . chr(strlen($r)) . $r; // ASN.1 INTEGER for r
        $sSequence = "\x02" . chr(strlen($s)) . $s; // ASN.1 INTEGER for s

        $der = "\x30" . chr(strlen($rSequence . $sSequence)) . $rSequence . $sSequence; // ASN.1 SEQUENCE

        return $der;
    }
}
