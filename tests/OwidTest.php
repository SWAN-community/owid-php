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
use SwanCommunity\Owid\Version;

/**
 * Tests the full sign, serialize, parse, and verify path locally, covering the
 * signing side that the cross language fixtures do not exercise.
 */
final class OwidTest extends TestCase
{
    /**
     * A locally signed OWID verifies with the crypto instance and with the
     * exported public key, and survives a base 64 round trip.
     */
    public function testSignAndSelfVerify(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $owid = $creator->signString('Hello World');
        $this->assertSame('example.com', $owid->domain);
        $this->assertSame(Version::Version3, $owid->version);
        $this->assertSame(64, strlen($owid->signature));
        $this->assertTrue($owid->verifyWithCrypto($crypto), 'should verify with crypto');

        $copy = Owid::fromBase64($owid->asBase64());
        $this->assertSame($owid->payload, $copy->payload);
        $this->assertTrue(
            $copy->verifyWithPublicKey($crypto->publicKeyPem()),
            'copy should verify with the public key'
        );
    }

    /**
     * A tampered copy of a locally signed OWID fails to verify.
     */
    public function testTamperedCopyFails(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $owid = $creator->signString('Hello World');
        $bytes = $owid->asByteArray();
        $last = strlen($bytes) - 1;
        $bytes[$last] = chr(ord($bytes[$last]) ^ 0xFF);
        $tampered = Owid::fromByteArray($bytes);
        $this->assertFalse(
            $tampered->verifyWithCrypto($crypto),
            'tampered OWID should not verify'
        );
    }

    /**
     * A locally built chain verifies with the same others in the same order
     * and fails with no others.
     */
    public function testSignedChainVerifies(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $root = $creator->signString('root');
        $party = new Owid();
        $party->payload = 'party';
        $creator->signWithOthers($party, [$root]);

        $this->assertTrue($root->verifyWithCrypto($crypto), 'root verifies alone');
        $this->assertTrue(
            $party->verifyWithCrypto($crypto, [$root]),
            'party verifies with the root'
        );
        $this->assertFalse(
            $party->verifyWithCrypto($crypto),
            'party fails with no others'
        );
    }

    /**
     * The payload accessors return the payload in each documented form.
     */
    public function testPayloadAccessors(): void
    {
        $owid = new Owid();
        $owid->payload = "\x01\x03";
        $this->assertSame("\x01\x03", $owid->payloadAsString());
        $this->assertSame('0103', $owid->payloadAsPrintable());
        $this->assertSame('AQM=', $owid->payloadAsBase64());
    }

    /**
     * The UTF-8 payload survives the round trip as text.
     */
    public function testUtf8PayloadRoundTrip(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $owid = $creator->signString(Fixtures::UTF8_PAYLOAD);
        $copy = Owid::fromBase64($owid->asBase64());
        $this->assertSame(Fixtures::UTF8_PAYLOAD, $copy->payloadAsString());
        $this->assertTrue($copy->verifyWithCrypto($crypto));
    }

    /**
     * The string conversion produces the base 64 form.
     */
    public function testToStringIsBase64(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $owid = $creator->signString('value');
        $this->assertSame($owid->asBase64(), (string) $owid);
    }

    /**
     * The age in minutes is not negative for an OWID created now.
     */
    public function testAgeMinutes(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('example.com', $crypto);
        $owid = $creator->signString('value');
        $this->assertGreaterThanOrEqual(0, $owid->ageMinutes());
        $this->assertLessThanOrEqual(1, $owid->ageMinutes());
    }
}
