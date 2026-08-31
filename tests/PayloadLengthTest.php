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
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\ParseStatus;
use SwanCommunity\Owid\Version;

/**
 * The payload length field of an OWID is whatever the sender declared, so
 * reading must check it against the bytes present before sizing anything by
 * it. These tests prove that a declared length which does not leave exactly
 * the signature after the payload is refused, that refusing it costs nothing
 * sized by the declared number, and that a correctly sized envelope still
 * parses. The 64 byte signature is the fixed tail every valid OWID ends with.
 */
final class PayloadLengthTest extends TestCase
{
    private const SIGNATURE_LENGTH = 64;

    /** The length of the payload used by the well formed envelopes. */
    private const PAYLOAD_LENGTH = 37;

    /**
     * A version 3 envelope, being the version byte, the domain with its
     * terminator, four minute bytes, the declared payload length, the payload
     * bytes given and the signature bytes given, so a test can make the
     * declared length and the bytes present disagree.
     */
    private static function envelope(
        int $declaredLength,
        string $payload,
        string $signature
    ): string {
        $buffer = '';
        Io::writeByte($buffer, Version::Version3->asByte());
        Io::writeString($buffer, '51d.es');
        Io::writeUint32($buffer, 1000);
        Io::writeUint32($buffer, $declaredLength);
        return $buffer . $payload . $signature;
    }

    private static function payload(): string
    {
        return str_repeat("\x5A", self::PAYLOAD_LENGTH);
    }

    private static function signature(
        int $length = self::SIGNATURE_LENGTH
    ): string {
        return str_repeat("\x99", $length);
    }

    /**
     * Reads the bytes expecting a refusal and returns the reason, so a test
     * can say which of the expected problems it was. Every part of a refusal
     * is asserted here, being that nothing was raised, that the read reports
     * it did not work, and that no value was handed back. A read that succeeds
     * fails the test.
     */
    private function refusal(string $bytes, string $label): ParseStatus
    {
        $result = Owid::tryFromByteArray($bytes);
        if ($result->ok) {
            $this->fail("$label should have been refused");
        }
        $this->assertNull($result->owid, "$label should hand back no value");
        $this->assertSame(0, $result->consumed, "$label should consume nothing");
        return $result->status;
    }

    /**
     * The declared length matches the bytes present, the signature is the last
     * 64 bytes, and the envelope parses to the same payload.
     */
    public function testDeclaredLengthMatchesParses(): void
    {
        $owid = Fixtures::parseBytes(self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature()
        ));
        $this->assertSame(self::payload(), $owid->payload);
        $this->assertSame(self::signature(), $owid->signature);
        $this->assertSame('51d.es', $owid->domain);
    }

    /**
     * A payload materially larger than an ordinary identifier remains valid
     * when its declaration and bytes agree. Application policy is separate
     * from format validity.
     */
    public function testMatchingOneMebibytePayloadParses(): void
    {
        $payload = str_repeat("\x5A", 1024 * 1024);

        $owid = Fixtures::parseBytes(self::envelope(
            strlen($payload),
            $payload,
            self::signature()
        ));

        $this->assertSame($payload, $owid->payload);
    }

    /**
     * A round trip through the library's own signing path still parses and
     * verifies, so the check agrees with what the library itself produces.
     */
    public function testLibraryOutputParses(): void
    {
        $crypto = Crypto::new();
        $creator = new Creator('51d.es', $crypto);
        $original = $creator->create(self::payload());
        $parsed = Fixtures::parseBytes($original->asByteArray());
        $this->assertSame(self::payload(), $parsed->payload);
        $this->assertTrue(
            $parsed->verifyWithCrypto($crypto),
            'parsed copy should verify'
        );
    }

    /**
     * One more or one fewer than the bytes present is refused, because either
     * overruns the payload or leaves bytes after the top-level value.
     */
    public function testDeclaredLengthOffByOneIsRefused(): void
    {
        $declaredLengths = [self::PAYLOAD_LENGTH - 1, self::PAYLOAD_LENGTH + 1];
        foreach ($declaredLengths as $declared) {
            $this->assertSame(
                ParseStatus::ByteCountMismatch,
                $this->refusal(
                    self::envelope($declared, self::payload(), self::signature()),
                    "declared $declared"
                )
            );
        }
    }

    /**
     * A byte after the signature is refused because a top-level decoder
     * requires the signature to end the envelope.
     */
    public function testTrailingByteAfterSignatureIsRefused(): void
    {
        $bytes = self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature()
        );

        $this->assertSame(
            ParseStatus::ByteCountMismatch,
            $this->refusal($bytes . "\x00", 'trailing byte')
        );
    }

    /**
     * A short signature is refused as a disagreement between the declaration
     * and the bytes rather than as data that stopped early. The declared
     * payload length is right for the payload, but what follows it is fewer
     * bytes than a signature, so the declared payload cannot leave exactly the
     * signature the version requires.
     */
    public function testShortSignatureIsRefused(): void
    {
        $bytes = self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature(self::SIGNATURE_LENGTH - 1)
        );

        $this->assertSame(
            ParseStatus::ByteCountMismatch,
            $this->refusal($bytes, '63 byte signature')
        );
    }

    /**
     * A large declaration whose payload bytes are absent is refused without
     * anything sized by the declared number. PHP cannot count allocations per
     * call, so the envelope of a few dozen bytes that declares 64 MiB, then
     * 2 GiB, then the largest unsigned 32 bit value while carrying none of
     * those bytes is read 1,000 times each. The numeric values remain valid
     * when the matching payload is present. The attempts must finish well
     * inside a second, which a read that sized a buffer by the declaration
     * could not do. Where the runtime can reset its peak memory figure
     * (PHP 8.2 and later) the peak during one refusal must also stay under
     * 64 KiB above the level before it.
     */
    public function testMismatchedLargeDeclarationIsRefusedQuickly(): void
    {
        $declaredLengths = [64 * 1024 * 1024, 0x7FFFFFFF, 0xFFFFFFFF];
        foreach ($declaredLengths as $declared) {
            $bytes = self::envelope($declared, '', '');
            $status = null;
            $start = hrtime(true);
            for ($attempt = 0; $attempt < 1000; $attempt++) {
                $status = $this->refusal($bytes, "declared $declared");
            }
            $elapsed = (hrtime(true) - $start) / 1e9;
            $this->assertSame(ParseStatus::ByteCountMismatch, $status);
            $this->assertLessThan(
                1.0,
                $elapsed,
                "declared $declared took {$elapsed}s for 1,000 attempts"
            );
            if (function_exists('memory_reset_peak_usage')) {
                $before = memory_get_usage();
                memory_reset_peak_usage();
                $this->refusal($bytes, "declared $declared");
                $peak = memory_get_peak_usage() - $before;
                $this->assertLessThan(
                    64 * 1024,
                    $peak,
                    "declared $declared raised peak memory by $peak bytes"
                );
            }
        }
    }

    /**
     * An empty payload, declared length zero, followed by the signature is a
     * valid OWID and parses. Having nothing to say is allowed.
     */
    public function testEmptyPayloadParses(): void
    {
        $owid = Fixtures::parseBytes(self::envelope(0, '', self::signature()));
        $this->assertSame('', $owid->payload);
        $this->assertSame(self::signature(), $owid->signature);
    }

    /**
     * The framed reader consumes one OWID and leaves the following envelope
     * for the next read, reporting how many bytes this one occupied, while the
     * byte array entry point stays strict about the end of the buffer.
     */
    public function testFramedReadLeavesFollowingEnvelopeUnread(): void
    {
        $firstBytes = self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature()
        );
        $secondBytes = self::envelope(0, '', self::signature());
        $buffer = $firstBytes . $secondBytes;

        $first = Owid::tryFromFrame($buffer);
        $this->assertTrue($first->ok, 'the first envelope should read');
        $this->assertSame(self::payload(), $first->owid->payload);
        $this->assertSame(strlen($firstBytes), $first->consumed);

        $second = Owid::tryFromFrame($buffer, $first->consumed);
        $this->assertTrue($second->ok, 'the second envelope should read');
        $this->assertSame('', $second->owid->payload);
        $this->assertSame(
            strlen($buffer),
            $first->consumed + $second->consumed,
            'the two envelopes should account for the whole buffer'
        );

        $this->assertSame(
            ParseStatus::ByteCountMismatch,
            $this->refusal($buffer, 'two envelopes on the exact surface')
        );
    }

    /**
     * A framed read of an envelope that stops early is data that ended rather
     * than a declaration that disagrees, because what follows a framed
     * envelope may be the next one, so the reader cannot say the bytes are
     * wrong, only that they are not all here.
     */
    public function testFramedReadOfATruncatedEnvelopeEndsEarly(): void
    {
        $bytes = self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature()
        );

        $result = Owid::tryFromFrame(substr($bytes, 0, strlen($bytes) - 1));

        $this->assertFalse($result->ok);
        $this->assertNull($result->owid);
        $this->assertSame(ParseStatus::UnexpectedEnd, $result->status);
    }

    /**
     * The signature length and the greatest number of characters a domain name
     * can hold are the bounds the reader works to, and both are published so a
     * caller can size its own limits.
     */
    public function testPublishedBounds(): void
    {
        $this->assertSame(64, OwidException::SIGNATURE_LENGTH);
        $this->assertSame(253, OwidException::MAXIMUM_DOMAIN_LENGTH);
    }
}
