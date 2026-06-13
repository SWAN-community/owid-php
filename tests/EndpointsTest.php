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
     * The creator end point body contains the JSON fields named in the
     * specification.
     */
    public function testCreatorResponseFields(): void
    {
        $creator = $this->newCreator();
        $body = Endpoints::creatorResponse($creator, 'Example Org', 'https://terms.example');
        $this->assertStringContainsString('publicKeySPKI', $body);
        $this->assertStringContainsString('contractURL', $body);
        $parsed = json_decode($body, true);
        $this->assertIsArray($parsed);
        $this->assertSame('example.com', $parsed['domain']);
        $this->assertSame('Example Org', $parsed['name']);
        $this->assertSame('https://terms.example', $parsed['contractURL']);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $parsed['publicKeySPKI']);
    }

    /**
     * The public key end point returns the PEM for the valid formats and
     * rejects unknown formats.
     */
    public function testPublicKeyResponseFormats(): void
    {
        $creator = $this->newCreator();
        foreach (['spki', 'pkcs'] as $format) {
            $body = Endpoints::publicKeyResponse($creator, $format);
            $this->assertStringContainsString(
                'BEGIN PUBLIC KEY',
                $body,
                "should return the PEM for format $format"
            );
        }
        $this->expectException(OwidException::class);
        Endpoints::publicKeyResponse($creator, 'other');
    }

    /**
     * The paths match the well known end points in the specification.
     */
    public function testPaths(): void
    {
        $this->assertSame('/owid/api/v3/creator', Endpoints::creatorPath(Version::Version3));
        $this->assertSame('/owid/api/v3/public-key', Endpoints::publicKeyPath(Version::Version3));
    }
}
