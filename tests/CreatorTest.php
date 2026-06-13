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
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\Version;

/**
 * Tests the creator that binds a domain to a signing crypto instance.
 */
final class CreatorTest extends TestCase
{
    /**
     * Signing sets the domain, the current version, and a 64 byte signature.
     */
    public function testSignSetsFields(): void
    {
        $creator = new Creator('example.com', Crypto::new());
        $owid = $creator->signString('Hello World');
        $this->assertSame('example.com', $owid->domain);
        $this->assertSame(Version::Version3, $owid->version);
        $this->assertSame(64, strlen($owid->signature));
    }

    /**
     * Signing overwrites whatever domain and version the OWID started with.
     */
    public function testSignOverwritesDomainAndVersion(): void
    {
        $creator = new Creator('example.com', Crypto::new());
        $owid = new Owid('other.com');
        $owid->version = Version::Version1;
        $owid->payload = 'value';
        $creator->sign($owid);
        $this->assertSame('example.com', $owid->domain);
        $this->assertSame(Version::Version3, $owid->version);
    }

    /**
     * The bytes accessor returns the same payload as the string accessor.
     */
    public function testSignBytesMatchesSignString(): void
    {
        $creator = new Creator('example.com', Crypto::new());
        $fromString = $creator->signString('value');
        $fromBytes = $creator->signBytes('value');
        $this->assertSame($fromString->payload, $fromBytes->payload);
    }

    /**
     * An empty domain is rejected.
     */
    public function testEmptyDomainRejected(): void
    {
        $this->expectException(OwidException::class);
        new Creator('   ', Crypto::new());
    }

    /**
     * A verify only crypto instance can not back a creator.
     */
    public function testVerifyOnlyCryptoRejected(): void
    {
        $crypto = Crypto::new();
        $verifier = Crypto::newVerifyOnly($crypto->publicKeyPem());
        $this->expectException(OwidException::class);
        new Creator('example.com', $verifier);
    }

    /**
     * A creator built from configuration signs OWIDs that verify.
     */
    public function testFromConfiguration(): void
    {
        $crypto = Crypto::new();
        $creator = Creator::fromConfiguration('example.com', $crypto->privateKeyPem());
        $owid = $creator->signString('value');
        $this->assertSame('example.com', $creator->domain());
        $this->assertTrue($owid->verifyWithPublicKey($crypto->publicKeyPem()));
    }

    /**
     * The creator exposes its domain and crypto instance.
     */
    public function testAccessors(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $this->assertSame('example.com', $creator->domain());
        $this->assertSame($crypto, $creator->crypto());
    }
}
