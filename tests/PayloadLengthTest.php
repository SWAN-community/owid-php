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
use SwanCommunity\Owid\Version;

/**
 * The payload length field of an OWID is whatever the sender declared, so
 * parsing must check it against the bytes present before sizing anything by
 * it. These tests prove that a declared length that does not leave exactly
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
     * terminator, four minute bytes, the declared payload length, the
     * payload bytes given and the signature bytes given, so a test can make
     * the declared length and the bytes present disagree.
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
     * Parses the bytes expecting a refusal and returns the message, so a
     * test can check what the message names. Every refusal must use the
     * library's own exception type, and a parse that is accepted fails the
     * test.
     */
    private function refusal(string $bytes, string $label): string
    {
        try {
            Owid::fromByteArray($bytes);
        } catch (OwidException $e) {
            return $e->getMessage();
        }
        $this->fail("$label should have been refused");
    }

    /**
     * The declared length matches the bytes present, the signature is the
     * last 64 bytes, and the envelope parses to the same payload.
     */
    public function testDeclaredLengthMatchesParses(): void
    {
        $owid = Owid::fromByteArray(self::envelope(
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

        $owid = Owid::fromByteArray(self::envelope(
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
        $original = $creator->signBytes(self::payload());
        $parsed = Owid::fromByteArray($original->asByteArray());
        $this->assertSame(self::payload(), $parsed->payload);
        $this->assertTrue(
            $parsed->verifyWithCrypto($crypto),
            'parsed copy should verify'
        );
    }

    /**
     * One more or one fewer than the bytes present is refused, because
     * either leaves something other than exactly the signature at the end.
     * The message names the declared length and the bytes present so the
     * caller can see what the sender got wrong.
     */
    public function testDeclaredLengthOffByOneIsRefused(): void
    {
        $present = self::PAYLOAD_LENGTH + self::SIGNATURE_LENGTH;
        $declaredLengths = [self::PAYLOAD_LENGTH - 1, self::PAYLOAD_LENGTH + 1];
        foreach ($declaredLengths as $declared) {
            $message = $this->refusal(
                self::envelope($declared, self::payload(), self::signature()),
                "declared $declared"
            );
            $this->assertStringContainsString("'$declared'", $message);
            $this->assertStringContainsString("'$present'", $message);
        }
    }

    /**
     * A byte after the signature is refused, because the signature must be
     * the end of the envelope. Before the check the extra byte was ignored.
     * The message names the bytes present, which include the extra byte.
     */
    public function testTrailingByteAfterSignatureIsRefused(): void
    {
        $bytes = self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature()
        );
        $message = $this->refusal($bytes . "\x00", 'trailing byte');
        $present = self::PAYLOAD_LENGTH + self::SIGNATURE_LENGTH + 1;
        $this->assertStringContainsString("'$present'", $message);
    }

    /**
     * A short signature is refused. The declared payload length is right for
     * the payload, but the bytes after it are fewer than a signature. The
     * message names the bytes present, one short of payload and signature.
     */
    public function testShortSignatureIsRefused(): void
    {
        $bytes = self::envelope(
            self::PAYLOAD_LENGTH,
            self::payload(),
            self::signature(self::SIGNATURE_LENGTH - 1)
        );
        $message = $this->refusal($bytes, '63 byte signature');
        $present = self::PAYLOAD_LENGTH + self::SIGNATURE_LENGTH - 1;
        $this->assertStringContainsString("'$present'", $message);
    }

    /**
     * A large declaration whose payload bytes are absent is refused without
     * anything sized by the declared number. PHP cannot count allocations
     * per call, so the envelope of a few dozen bytes that declares 64 MiB,
     * then 2 GiB, then the largest unsigned 32 bit value while carrying none
     * of those bytes is parsed 1,000 times each. The numeric values remain
     * valid when the matching payload is present. The attempts must finish
     * well inside a second, which a parse that sized a buffer by the
     * declaration could not do. Where the runtime
     * can reset its peak memory figure (PHP 8.2 and later) the peak during
     * one refusal must also stay under 64 KiB above the level before it.
     */
    public function testMismatchedLargeDeclarationIsRefusedQuickly(): void
    {
        $declaredLengths = [64 * 1024 * 1024, 0x7FFFFFFF, 0xFFFFFFFF];
        foreach ($declaredLengths as $declared) {
            $bytes = self::envelope($declared, '', '');
            $message = '';
            $start = hrtime(true);
            for ($attempt = 0; $attempt < 1000; $attempt++) {
                $message = $this->refusal($bytes, "declared $declared");
            }
            $elapsed = (hrtime(true) - $start) / 1e9;
            $this->assertStringContainsString("'$declared'", $message);
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
     * valid OWID and parses.
     */
    public function testEmptyPayloadParses(): void
    {
        $owid = Owid::fromByteArray(self::envelope(0, '', self::signature()));
        $this->assertSame('', $owid->payload);
        $this->assertSame(self::signature(), $owid->signature);
    }
}
