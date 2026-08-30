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
 * The domain of an OWID is stored as text followed by a zero terminator, and
 * the terminator is whatever the sender wrote, so the search for it must stop
 * at the greatest number of characters a domain name can hold rather than run
 * to the end of the buffer. These tests prove that a domain of the greatest
 * length still parses, that one character more is refused, that a buffer with
 * no terminator at all is refused for a cost that does not grow with the
 * buffer, and that what the library itself signs still parses.
 */
final class DomainLengthTest extends TestCase
{
    /** The length of the fixed tail every valid OWID ends with. */
    private const SIGNATURE_LENGTH = 64;

    /**
     * Returns a domain of the length given, built from labels of no more than
     * 63 characters separated by dots so it is shaped like a real name rather
     * than one long run of letters.
     *
     * @throws OwidException when the arithmetic below builds the wrong length.
     */
    private static function domain(int $length): string
    {
        $labels = [];
        $remaining = $length;
        while ($remaining > 64) {
            $labels[] = str_repeat('a', 63);
            $remaining -= 64;
        }
        $labels[] = str_repeat('a', $remaining);
        $domain = implode('.', $labels);
        if (strlen($domain) !== $length) {
            throw new OwidException('test domain built to the wrong length');
        }
        return $domain;
    }

    /**
     * A version 3 envelope carrying the domain given, followed by a date, an
     * empty payload and the signature. The domain and its terminator are
     * appended here rather than through Io::writeString because these tests
     * build domains the write side now refuses, and the point of them is
     * what the read side does with such bytes when they arrive from
     * somewhere else.
     */
    private static function envelope(string $domain): string
    {
        $buffer = '';
        Io::writeByte($buffer, Version::Version3->asByte());
        $buffer .= $domain . chr(0);
        Io::writeUint32($buffer, 1000);
        Io::writeUint32($buffer, 0);
        return $buffer . str_repeat("\x99", self::SIGNATURE_LENGTH);
    }

    /**
     * Parses the bytes expecting a refusal and returns the message, so a test
     * can check what the message names. Every refusal must use the library's
     * own exception type, and a parse that is accepted fails the test.
     */
    private function refusal(string $bytes, string $label): string
    {
        try {
            Owid::fromByteArray($bytes);
        } catch (OwidException $e) {
            $this->addToAssertionCount(1);
            return $e->getMessage();
        }
        $this->fail("$label should have been refused");
    }

    /**
     * A domain of the greatest length a domain name can hold parses, and the
     * envelope round trips back to the same bytes.
     */
    public function testMaximumLengthDomainParses(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH);
        $bytes = self::envelope($domain);

        $owid = Owid::fromByteArray($bytes);

        $this->assertSame($domain, $owid->domain);
        $this->assertSame(
            OwidException::MAXIMUM_DOMAIN_LENGTH,
            strlen($owid->domain)
        );
        $this->assertSame($bytes, $owid->asByteArray());
    }

    /**
     * One character more than a domain name can hold is refused, even though
     * the terminator is present, because the parse stops at the bound.
     */
    public function testDomainOneOverMaximumIsRefused(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH + 1);

        $message = $this->refusal(self::envelope($domain), 'over long domain');

        $maximum = OwidException::MAXIMUM_DOMAIN_LENGTH;
        $this->assertStringContainsString("'$maximum'", $message);
    }

    /**
     * Returns the seconds taken to refuse the bytes the number of times
     * given, and puts the last refusal message into the reference given.
     */
    private function timeRefusals(
        string $bytes,
        int $attempts,
        string &$message
    ): float {
        $start = hrtime(true);
        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $message = $this->refusal($bytes, 'unterminated domain');
        }
        return (hrtime(true) - $start) / 1e9;
    }

    /**
     * A buffer whose domain field has no terminator at all is refused for a
     * cost that does not grow with the buffer. PHP cannot count the bytes a
     * single call examines, so the proof is the time taken, and it is taken
     * twice over buffers sixteen times apart so the result does not depend on
     * how fast the machine is. A search running to the end of the buffer
     * costs sixteen times as much on the larger one, whereas a search
     * stopping at the bound costs the same on both, so the larger is required
     * to stay inside four times the smaller. The small allowance added to
     * that limit absorbs timer noise, because at the bound both runs take
     * only a few thousandths of a second. A plain ceiling on the larger run
     * is kept as well, in the style of the payload length checks. The peak
     * memory during one refusal is held to 64 KiB above the level before it,
     * where the runtime can reset its peak figure, which is PHP 8.2 and
     * later, so nothing is sized by the run of characters either.
     */
    public function testUnterminatedDomainIsRefusedWithoutReadingTheBuffer(): void
    {
        $prefix = chr(Version::Version3->asByte());
        $small = $prefix . str_repeat('a', 1024 * 1024);
        $large = $prefix . str_repeat('a', 16 * 1024 * 1024);
        $message = '';

        $smallSeconds = $this->timeRefusals($small, 1000, $message);
        $largeSeconds = $this->timeRefusals($large, 1000, $message);

        $this->assertLessThan(
            4 * $smallSeconds + 0.05,
            $largeSeconds,
            "sixteen times the buffer took {$largeSeconds}s against " .
            "{$smallSeconds}s, so the cost grows with the buffer"
        );
        $this->assertLessThan(
            1.0,
            $largeSeconds,
            "unterminated domain took {$largeSeconds}s for 1,000 attempts"
        );
        $maximum = OwidException::MAXIMUM_DOMAIN_LENGTH;
        $this->assertStringContainsString("'$maximum'", $message);
        if (function_exists('memory_reset_peak_usage')) {
            $before = memory_get_usage();
            memory_reset_peak_usage();
            $this->refusal($large, 'unterminated domain');
            $peak = memory_get_peak_usage() - $before;
            $this->assertLessThan(
                64 * 1024,
                $peak,
                "unterminated domain raised peak memory by $peak bytes"
            );
        }
    }

    /**
     * A buffer holding only the version byte and characters filling the bound
     * exactly, with no terminator after them, is refused rather than read as
     * a domain, because the terminator has to be present within the bound and
     * not merely absent from it.
     */
    public function testDomainFillingTheBoundWithNoTerminatorIsRefused(): void
    {
        $bytes = chr(Version::Version3->asByte()) .
            str_repeat('a', OwidException::MAXIMUM_DOMAIN_LENGTH);

        $this->refusal($bytes, 'domain filling the bound');
    }

    /**
     * A creator is refused a domain one character longer than a domain name
     * can hold, at the point the domain is supplied, so the caller is told
     * when the configuration is wrong rather than when an OWID is later
     * serialized. Both ways of making a creator are covered, and the message
     * names the maximum.
     */
    public function testCreatorRefusesDomainOverMaximum(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH + 1);
        $maximum = OwidException::MAXIMUM_DOMAIN_LENGTH;
        $crypto = Crypto::new();

        try {
            new Creator($domain, $crypto);
            $this->fail('over long creator domain should have been refused');
        } catch (OwidException $e) {
            $this->assertStringContainsString("'$maximum'", $e->getMessage());
        }

        try {
            Creator::fromConfiguration($domain, $crypto->privateKeyPem());
            $this->fail('over long configured domain should have been refused');
        } catch (OwidException $e) {
            $this->assertStringContainsString("'$maximum'", $e->getMessage());
        }
    }

    /**
     * The serialization refuses the same domain as well, so a value that
     * reached the public domain field by a route other than the creator is
     * still refused. The data the signature is calculated over is built the
     * same way, so the refusal reaches that too. A domain of exactly the
     * greatest length is written and parses back unchanged, so this is a
     * refusal at the top of the range and nothing else.
     */
    public function testWriteRefusesDomainOverMaximum(): void
    {
        $maximum = OwidException::MAXIMUM_DOMAIN_LENGTH;
        $owid = new Owid();
        $owid->payload = 'value';
        $owid->signature = str_repeat(chr(0x99), self::SIGNATURE_LENGTH);

        $owid->domain = self::domain($maximum + 1);
        foreach (['asByteArray', 'dataForCrypto'] as $method) {
            try {
                $owid->$method();
                $this->fail("$method should have refused the long domain");
            } catch (OwidException $e) {
                $this->assertStringContainsString(
                    "'$maximum'",
                    $e->getMessage()
                );
            }
        }

        $owid->domain = self::domain($maximum);
        $parsed = Owid::fromByteArray($owid->asByteArray());
        $this->assertSame($owid->domain, $parsed->domain);
    }

    /**
     * The refusal happens before any signature is calculated. A creator is
     * refused before its crypto instance is looked at, which is shown by
     * handing the constructor an instance that can only verify, because a
     * message naming the key rather than the maximum would mean the two
     * checks ran the other way round. A domain that arrives on another OWID
     * covered by the signature is refused while the data to sign is being
     * built, which is before the signing key is used, so the signature field
     * is left holding exactly what it held before.
     */
    public function testRefusalHappensBeforeAnySignature(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH + 1);
        $maximum = OwidException::MAXIMUM_DOMAIN_LENGTH;
        $crypto = Crypto::new();
        $verifyOnly = Crypto::newVerifyOnly($crypto->publicKeyPem());

        try {
            new Creator($domain, $verifyOnly);
            $this->fail('over long creator domain should have been refused');
        } catch (OwidException $e) {
            $this->assertStringContainsString("'$maximum'", $e->getMessage());
        }

        $other = new Owid();
        $other->domain = $domain;
        $other->payload = 'other';
        $other->signature = str_repeat(chr(0x11), self::SIGNATURE_LENGTH);
        $owid = new Owid();
        $owid->payload = 'value';
        $owid->signature = str_repeat(chr(0x22), self::SIGNATURE_LENGTH);

        try {
            (new Creator('51d.es', $crypto))->signWithOthers($owid, [$other]);
            $this->fail('over long domain on another OWID should be refused');
        } catch (OwidException $e) {
            $this->assertStringContainsString("'$maximum'", $e->getMessage());
        }
        $this->assertSame(
            str_repeat(chr(0x22), self::SIGNATURE_LENGTH),
            $owid->signature,
            'the signature should not have been calculated'
        );
    }

    /**
     * What the library itself signs still parses and still verifies, with an
     * ordinary domain and with one of the greatest length, so the bound is
     * not retrospective on anything real.
     */
    public function testLibraryOutputParses(): void
    {
        $domains = [
            '51d.es',
            self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH),
        ];
        foreach ($domains as $domain) {
            $crypto = Crypto::new();
            $creator = new Creator($domain, $crypto);
            $original = $creator->signString('value');

            $parsed = Owid::fromByteArray($original->asByteArray());

            $this->assertSame($domain, $parsed->domain);
            $this->assertTrue(
                $parsed->verifyWithCrypto($crypto),
                "parsed copy of '$domain' should verify"
            );
        }
    }
}
