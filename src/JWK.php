<?php

declare(strict_types=1);

namespace Flytachi\Jwt;

use Flytachi\Jwt\Entity\PublicKey;
use InvalidArgumentException;
use RuntimeException;

/**
 * A secure and strictly-typed parser for JSON Web Key (JWK) Sets.
 * Provides static methods to convert JWK arrays into PublicKey objects.
 * This implementation is aligned with industry-standard libraries for maximum compatibility.
 */
final class JWK
{
    /**
     * Parses a JWK Set into an array of PublicKey objects, indexed by Key ID (kid).
     *
     * @param array<string, mixed> $jwksData The associative array decoded from a JWKS JSON.
     * @return array<string, PublicKey> A map of [kid => PublicKey].
     */
    public static function parseKeySet(array $jwksData): array
    {
        if (!isset($jwksData['keys']) || !is_array($jwksData['keys'])) {
            throw new InvalidArgumentException('Invalid JWKS format: "keys" array is missing.');
        }

        $publicKeys = [];
        foreach ($jwksData['keys'] as $jwkData) {
            if (!is_array($jwkData) || empty($jwkData['kid'])) {
                continue;
            }
            $kid = (string) $jwkData['kid'];
            try {
                $publicKeys[$kid] = self::parseKey($jwkData);
            } catch (\Exception $e) {
                // For debugging: error_log("Skipping key '$kid' due to parsing error: " . $e->getMessage());
            }
        }
        return $publicKeys;
    }

    /**
     * Parses a single JSON Web Key into a PublicKey object.
     *
     * @param array<string, mixed> $jwkData The individual JWK data.
     * @return PublicKey The parsed public key object.
     */
    public static function parseKey(array $jwkData): PublicKey
    {
        $keyType = $jwkData['kty'] ?? null;
        if (!$keyType) {
            throw new InvalidArgumentException('JWK must contain a "kty" (Key Type) parameter.');
        }

        $algorithm = $jwkData['alg'] ?? null;
        if (!$algorithm) {
            throw new InvalidArgumentException('JWK must contain an "alg" (Algorithm) parameter for verification.');
        }

        switch ($keyType) {
            case 'RSA':
                $n = $jwkData['n'] ?? null;
                $e = $jwkData['e'] ?? null;
                if (!$n || !$e) {
                    throw new InvalidArgumentException('RSA JWK requires "n" and "e" parameters.');
                }

                $pem = self::createPemFromRsa($n, $e);
                $keyMaterial = openssl_pkey_get_public($pem);
                if ($keyMaterial === false) {
                    throw new RuntimeException('Failed to parse RSA public key: ' . openssl_error_string());
                }
                return new PublicKey($keyMaterial, $algorithm);

            case 'EC':
                $crv = $jwkData['crv'] ?? null;
                $x = $jwkData['x'] ?? null;
                $y = $jwkData['y'] ?? null;
                if (!$crv || !$x || !$y) {
                    throw new InvalidArgumentException('EC JWK requires "crv", "x", and "y" parameters.');
                }

                $pem = self::createPemFromEc($crv, $x, $y);
                $keyMaterial = openssl_pkey_get_public($pem);
                if ($keyMaterial === false) {
                    throw new RuntimeException(
                        'Failed to parse EC public key from JWK. Check JWK data for'
                        . ' correctness. OpenSSL error: ' . openssl_error_string()
                    );
                }
                return new PublicKey($keyMaterial, $algorithm);

            case 'oct':
                $keySecret = $jwkData['k'] ?? null;
                if (!$keySecret) {
                    throw new InvalidArgumentException('oct JWK requires a "k" (Key Value) parameter.');
                }

                return new PublicKey(self::base64UrlDecode($keySecret), $algorithm);

            default:
                throw new InvalidArgumentException("Unsupported key type: {$keyType}");
        }
    }

    // --- PEM Creation Methods ---

    /**
     * Creates a PEM-formatted public key from RSA modulus (n) and exponent (e).
     */
    private static function createPemFromRsa(string $n, string $e): string
    {
        $modulus = self::base64UrlDecode($n);
        $exponent = self::base64UrlDecode($e);

        // Create the SubjectPublicKeyInfo structure.
        $publicKeyInfo = self::encodeSequence(
        // AlgorithmIdentifier (rsaEncryption OID)
            self::encodeSequence(
                self::encodeOid('1.2.840.113549.1.1.1') . // OID for rsaEncryption
                "\x05\x00" // NULL parameters
            ) .
            // PublicKey BIT STRING
            self::encodeBitString(
                "\x00" . // Prepend unused bits byte
                // RSAPublicKey SEQUENCE
                self::encodeSequence(
                    self::encodeInteger($modulus) .
                    self::encodeInteger($exponent)
                )
            )
        );

        return "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($publicKeyInfo), 64, "\n") .
            "-----END PUBLIC KEY-----\n";
    }

    /**
     * Creates a PEM-formatted public key from EC curve (crv) and coordinates (x, y).
     */
    private static function createPemFromEc(string $crv, string $x, string $y): string
    {
        $crvData = [
            'P-256' => ['oid' => '1.2.840.10045.3.1.7', 'size' => 32],
            'P-384' => ['oid' => '1.3.132.0.34', 'size' => 48],
            'P-521' => ['oid' => '1.3.132.0.35', 'size' => 66],
        ];

        if (!isset($crvData[$crv])) {
            throw new InvalidArgumentException("Unsupported EC curve: $crv");
        }

        // Create the SubjectPublicKeyInfo structure.
        $publicKeyInfo = self::encodeSequence(
        // AlgorithmIdentifier (id-ecPublicKey + curve OID)
            self::encodeSequence(
                self::encodeOid('1.2.840.10045.2.1') . // OID for id-ecPublicKey
                self::encodeOid($crvData[$crv]['oid'])   // OID for the curve itself
            ) .
            // PublicKey BIT STRING
            self::encodeBitString(
                "\x00" . // Prepend unused bits byte
                "\x04" . // Uncompressed point indicator
                str_pad(self::base64UrlDecode($x), $crvData[$crv]['size'], "\x00", STR_PAD_LEFT) .
                str_pad(self::base64UrlDecode($y), $crvData[$crv]['size'], "\x00", STR_PAD_LEFT)
            )
        );

        return "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($publicKeyInfo), 64, "\n") .
            "-----END PUBLIC KEY-----\n";
    }

    // --- ASN.1 Encoding Helpers ---

    private static function encodeSequence(string $value): string
    {
        return "\x30" . self::encodeLength(strlen($value)) . $value;
    }

    private static function encodeInteger(string $value): string
    {
        // If the high-order bit is set, prepend a null byte to represent it as a positive integer.
        if (ord($value[0]) > 0x7F) {
            $value = "\x00" . $value;
        }
        return "\x02" . self::encodeLength(strlen($value)) . $value;
    }

    private static function encodeBitString(string $value): string
    {
        return "\x03" . self::encodeLength(strlen($value)) . $value;
    }

    private static function encodeOid(string $oid): string
    {
        $parts = explode('.', $oid);
        $first = (int) array_shift($parts);
        $second = (int) array_shift($parts);
        $binary = chr($first * 40 + $second);

        foreach ($parts as $part) {
            $value = (int) $part;
            $buffer = '';
            do {
                $byte = $value & 0x7F;
                $value >>= 7;
                if ($buffer !== '') {
                    $byte |= 0x80;
                }
                $buffer = chr($byte) . $buffer;
            } while ($value > 0);
            $binary .= $buffer;
        }
        return "\x06" . self::encodeLength(strlen($binary)) . $binary;
    }

    private static function encodeLength(int $length): string
    {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($temp)) . $temp;
    }

    private static function base64UrlDecode(string $data): string
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
