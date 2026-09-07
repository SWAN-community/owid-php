<?php

/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

declare(strict_types=1);

namespace SwanCommunity\Owid\Tests;

use PHPUnit\Framework\TestCase;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Endpoints;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\Version;

/**
 * Tests the framework agnostic well known end point helpers.
 */
final class EndpointsTest extends TestCase
{
    private function newCreator(): Creator
    {
        return new Creator('example.com', Crypto::new());
    }

    /**
     * The public key end point answers the key as publicKey in the spki
     * format, which is echoed and which a request naming no format receives,
     * and refuses every other format, pkcs among them.
     */
    public function testPublicKeyResponseFormats(): void
    {
        $creator = $this->newCreator();
        foreach (['spki', null, ''] as $format) {
            $body = Endpoints::publicKeyResponse($creator, $format);
            $answer = json_decode($body, true);
            $this->assertSame('spki', $answer['format'], 'the format is echoed, and taken as spki where absent');
            $this->assertStringContainsString(
                'BEGIN PUBLIC KEY',
                $answer['publicKey'],
                'should return the PEM as publicKey'
            );
            $this->assertNull($answer['validFrom'], 'a single key has no schedule');
            $this->assertNull($answer['validTo']);
        }
        foreach (['pkcs', 'other', 'SPKI'] as $format) {
            try {
                Endpoints::publicKeyResponse($creator, $format);
                $this->fail("format $format should be refused");
            } catch (OwidException $refused) {
                $this->assertStringContainsString('spki', $refused->getMessage());
            }
        }
    }

    /**
     * The path matches the well known end point in the specification.
     */
    public function testPaths(): void
    {
        $this->assertSame('/owid/api/v3/public-key', Endpoints::publicKeyPath(Version::Version3));
    }
}
