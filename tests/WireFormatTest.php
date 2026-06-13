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
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\Version;

/**
 * Tests the canonical wire format vectors round trip byte exact and the
 * payload accessors behave as the specification requires.
 */
final class WireFormatTest extends TestCase
{
    /**
     * Each canonical vector decodes, parses, and re-serializes to the same
     * bytes. The comparison is on bytes because the vectors are unpadded and
     * the encoder pads.
     */
    public function testCanonicalVectorsRoundTripByteExact(): void
    {
        $vectors = [
            'creator' => Fixtures::CANONICAL_CREATOR,
            'supplier' => Fixtures::CANONICAL_SUPPLIER,
            'bad' => Fixtures::CANONICAL_BAD,
        ];
        foreach ($vectors as $name => $value) {
            $bytes = base64_decode($value, true);
            $this->assertNotFalse($bytes, "vector $name should decode");
            $owid = Owid::fromByteArray($bytes);
            $this->assertSame(
                bin2hex($bytes),
                bin2hex($owid->asByteArray()),
                "vector $name should round trip byte exact"
            );
        }
    }

    /**
     * The creator vector parses with the documented field values.
     */
    public function testCreatorVectorFields(): void
    {
        $owid = Owid::fromBase64(Fixtures::CANONICAL_CREATOR);
        $this->assertSame('51db.uk', $owid->domain);
        $this->assertSame(Version::Version2, $owid->version);
        $this->assertSame(341, strlen($owid->payload));
        $this->assertSame('2021-04-06T12:59Z', $owid->date->format('Y-m-d\TH:i\Z'));
        $signature = $owid->signature;
        $this->assertSame(64, strlen($signature));
        $this->assertSame(74, ord($signature[0]), 'first signature byte');
        $this->assertSame(64, ord($signature[63]), 'last signature byte');
    }

    /**
     * The supplier vector exposes the payload in each requested form.
     */
    public function testSupplierVectorPayloadForms(): void
    {
        $owid = Owid::fromBase64(Fixtures::CANONICAL_SUPPLIER);
        $this->assertSame('pop-up.swan-demo.uk', $owid->domain);
        $this->assertSame("\x01\x03", $owid->payload);
        $this->assertSame('0103', $owid->payloadAsPrintable());
        $this->assertSame('AQM=', $owid->payloadAsBase64());
    }

    /**
     * The bad vector parses but is not asserted to verify.
     */
    public function testBadVectorParses(): void
    {
        $owid = Owid::fromBase64(Fixtures::CANONICAL_BAD);
        $this->assertSame('badssp.swan-demo.uk', $owid->domain);
        $this->assertSame(64, strlen($owid->signature));
    }

    /**
     * Unpadded base 64 input decodes the same as padded input.
     */
    public function testDecodeAcceptsPaddedAndUnpadded(): void
    {
        $padded = Owid::fromBase64(Fixtures::CANONICAL_SUPPLIER . '');
        $reEncoded = $padded->asBase64();
        $this->assertStringEndsWith('=', $reEncoded, 'encoding always pads');
        $fromPadded = Owid::fromBase64($reEncoded);
        $this->assertSame(
            bin2hex($padded->asByteArray()),
            bin2hex($fromPadded->asByteArray())
        );
    }

    /**
     * An empty OWID marker is a single zero byte and reads back as the empty
     * version.
     */
    public function testEmptyOwidMarker(): void
    {
        $buffer = '';
        Owid::emptyToBuffer($buffer);
        $this->assertSame("\x00", $buffer);
        $owid = Owid::fromByteArray($buffer);
        $this->assertSame(Version::Empty, $owid->version);
    }

    /**
     * An unknown version byte is rejected.
     */
    public function testUnknownVersionRejected(): void
    {
        $this->expectException(OwidException::class);
        Owid::fromByteArray("\x09rest");
    }

    /**
     * A truncated buffer is rejected.
     */
    public function testTruncatedBufferRejected(): void
    {
        $bytes = base64_decode(Fixtures::CANONICAL_SUPPLIER, true);
        $this->assertNotFalse($bytes);
        $this->expectException(OwidException::class);
        Owid::fromByteArray(substr($bytes, 0, 10));
    }
}
