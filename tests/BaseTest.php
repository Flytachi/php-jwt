<?php

namespace Flytachi\Jwt\Tests;

use Flytachi\Jwt\JWT;
use Flytachi\Jwt\Entity\JwtPayload;
use Flytachi\Jwt\Entity\PrivateKey;
use Flytachi\Jwt\Entity\PublicKey;
use PHPUnit\Framework\TestCase;

class BaseTest extends TestCase
{
    public function testEncodeAndDecode()
    {
        $jwtToken = JWT::encode(new JwtPayload([
            'sub' => 'test'
        ]), new PrivateKey('secret', 'HS256'));

        $payload = JWT::decode($jwtToken, [new PublicKey('secret', 'HS256')]);
        self::assertEquals($payload->getClaim('sub'), 'test');
    }
}
