# Flytachi JWT

[![Latest Version on Packagist](https://img.shields.io/packagist/v/flytachi/jwt.svg?style=flat-square )](https://packagist.org/packages/flytachi/jwt )
[![PHP Version Require](https://img.shields.io/packagist/php-v/flytachi/jwt.svg?style=flat-square )](https://packagist.org/packages/flytachi/jwt )
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square )](https://opensource.org/licenses/MIT )

**Flytachi JWT** — A modern, secure, and strongly typed PHP library for encoding and decoding JSON Web Tokens (JWT). 
It is built with a focus on security, ease of use, and maximum standards compliance, including full support for JSON Web Key Sets (JWKS).

## Key Features

*   **Security-first:** Uses strict typing and value objects to prevent errors. Signature verification is protected against (`timing attacks`).
*   **Modern design:** Written in modern PHP (requires PHP 8.1+) and follows best practices, including PSR standards.
*   **Full JWKS support:** Built-in `JWK` parser makes it easy to work with public key sets from any provider (Google, Apple, Auth0, Privy, etc.).
*   **Support for all popular algorithms:**
    *   **HMAC:** `HS256`, `HS384`, `HS512`
    *   **RSA:** `RS256`, `RS384`, `RS512`
    *   **ECDSA:** `ES256`, `ES384`, `ES512`
*   **Simple and clean API:** Convenient static methods for encoding and decoding tokens.
*   **Robust error handling:** Uses specific exceptions (`JWTException`) so you can easily catch and handle any token-related issues.

## Installation

You can install the library via [Composer](https://getcomposer.org/ ):

```bash
  composer require flytachi/jwt
```

### Usage Examples

```php
use Flytachi\Jwt\JWT;
use Flytachi\Jwt\Entity\JwtPayload;
use Flytachi\Jwt\Entity\PrivateKey;
use Flytachi\Jwt\Entity\PublicKey;

// encode
$jwtToken = JWT::encode(
    new JwtPayload([
        'iss' => 'https://domain.com',      // Issuer: who issued the token
        'sub' => 'user-12345',              // Subject: for whom the token is intended (user ID)
        'aud' => 'https://api.domain.com',  // Audience: what service is the token intended for?
        'iat' => time(),                    // Issued At: token issue time (Unix timestamp)
        'nbf' => time(),                    // Not Before: time from which the token becomes valid
        'exp' => time() + 3600,             // Expiration Time: time when the token expires (in 1 hour)
    ]),
    new PrivateKey('secret', 'HS256')
);

// decode
$payload = JWT::decode($jwtToken, [new PublicKey('secret', 'HS256')]);
$userId = $payload->getClaim('sub');
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.