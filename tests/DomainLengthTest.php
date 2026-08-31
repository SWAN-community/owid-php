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
     * build domains the write side refuses, and the point of them is what the
     * read side does with such bytes when they arrive from somewhere else.
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
     * Reads the bytes expecting a refusal and returns the reason. Nothing may
     * be raised, the read must report that it did not work, and no value may
     * be handed back. A read that succeeds fails the test.
     */
    private function refusal(string $bytes, string $label): ParseStatus
    {
        $result = Owid::tryFromByteArray($bytes);
        if ($result->ok) {
            $this->fail("$label should have been refused");
        }
        $this->assertNull($result->owid, "$label should hand back no value");
        return $result->status;
    }

    /**
     * Returns true when the action raises the library's exception naming the
     * greatest number of characters a domain name can hold, which is how the
     * write side reports the same bound the read side works to.
     */
    private function refusalNamesMaximum(callable $action): bool
    {
        try {
            $action();
        } catch (OwidException $e) {
            return str_contains(
                $e->getMessage(),
                "'" . OwidException::MAXIMUM_DOMAIN_LENGTH . "'"
            );
        }
        return false;
    }

    /**
     * A domain of the greatest length a domain name can hold parses, and the
     * envelope round trips back to the same bytes.
     */
    public function testMaximumLengthDomainParses(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH);
        $bytes = self::envelope($domain);

        $owid = Fixtures::parseBytes($bytes);

        $this->assertSame($domain, $owid->domain);
        $this->assertSame(
            OwidException::MAXIMUM_DOMAIN_LENGTH,
            strlen($owid->domain)
        );
        $this->assertSame($bytes, $owid->asByteArray());
    }

    /**
     * One character more than a domain name can hold is refused, even though
     * the terminator is present, because the read stops at the bound and what
     * runs past it cannot be a domain.
     */
    public function testDomainOneOverMaximumIsRefused(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH + 1);

        $this->assertSame(
            ParseStatus::InvalidDomainEncoding,
            $this->refusal(self::envelope($domain), 'over long domain')
        );
    }

    /**
     * Returns the seconds taken to refuse the bytes the number of times given,
     * and puts the last reason into the reference given.
     */
    private function timeRefusals(
        string $bytes,
        int $attempts,
        ?ParseStatus &$status
    ): float {
        $start = hrtime(true);
        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $status = $this->refusal($bytes, 'unterminated domain');
        }
        return (hrtime(true) - $start) / 1e9;
    }

    /**
     * A buffer whose domain field has no terminator at all is refused for a
     * cost that does not grow with the buffer. PHP cannot count the bytes a
     * single call examines, so the proof is the time taken, and it is taken
     * twice over buffers sixteen times apart so the result does not depend on
     * how fast the machine is. A search running to the end of the buffer costs
     * sixteen times as much on the larger one, whereas a search stopping at
     * the bound costs the same on both, so the larger is required to stay
     * inside four times the smaller. The small allowance added to that limit
     * absorbs timer noise, because at the bound both runs take only a few
     * thousandths of a second. A plain ceiling on the larger run is kept as
     * well, in the style of the payload length checks. The peak memory during
     * one refusal is held to 64 KiB above the level before it, where the
     * runtime can reset its peak figure, which is PHP 8.2 and later, so
     * nothing is sized by the run of characters either.
     */
    public function testUnterminatedDomainIsRefusedWithoutReadingTheBuffer(): void
    {
        $prefix = chr(Version::Version3->asByte());
        $small = $prefix . str_repeat('a', 1024 * 1024);
        $large = $prefix . str_repeat('a', 16 * 1024 * 1024);
        $status = null;

        $smallSeconds = $this->timeRefusals($small, 1000, $status);
        $largeSeconds = $this->timeRefusals($large, 1000, $status);

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
        $this->assertSame(ParseStatus::InvalidDomainEncoding, $status);
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
     * exactly, with no terminator after them, is data that stopped rather than
     * a domain that cannot be valid, because everything read so far could
     * still have been a domain had the buffer gone on.
     */
    public function testDomainFillingTheBoundWithNoTerminatorIsRefused(): void
    {
        $bytes = chr(Version::Version3->asByte()) .
            str_repeat('a', OwidException::MAXIMUM_DOMAIN_LENGTH);

        $this->assertSame(
            ParseStatus::UnexpectedEnd,
            $this->refusal($bytes, 'domain filling the bound')
        );
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
        $crypto = Crypto::new();

        $this->assertTrue($this->refusalNamesMaximum(
            fn () => new Creator($domain, $crypto)
        ), 'the creator should refuse the domain');
        $this->assertTrue($this->refusalNamesMaximum(
            fn () => Creator::fromConfiguration($domain, $crypto->privateKeyPem())
        ), 'the configured creator should refuse the domain');
    }

    /**
     * The write side refuses the same domain, so this library cannot produce
     * bytes it would then refuse to read. The check is made through the write
     * helper directly because no OWID can carry such a domain any more: one
     * arrives only by being read, which stops at the bound, or by being
     * created, where the creator refuses it. A domain of exactly the greatest
     * length is written and read back unchanged, so this is a refusal at the
     * top of the range and nothing else.
     */
    public function testWriteRefusesDomainOverMaximum(): void
    {
        $maximum = OwidException::MAXIMUM_DOMAIN_LENGTH;

        $this->assertTrue($this->refusalNamesMaximum(function () use ($maximum) {
            $buffer = '';
            Io::writeString($buffer, self::domain($maximum + 1));
        }), 'writing an over long domain should be refused');

        $atBound = self::domain($maximum);
        $parsed = Fixtures::parseBytes(self::envelope($atBound));
        $this->assertSame($atBound, $parsed->domain);
    }

    /**
     * The refusal happens before any signature is calculated. A creator is
     * refused before its crypto instance is looked at, which is shown by
     * handing the constructor an instance that can only verify, because a
     * message naming the key rather than the maximum would mean the two checks
     * ran the other way round.
     */
    public function testRefusalHappensBeforeAnySignature(): void
    {
        $domain = self::domain(OwidException::MAXIMUM_DOMAIN_LENGTH + 1);
        $crypto = Crypto::new();
        $verifyOnly = Crypto::newVerifyOnly($crypto->publicKeyPem());

        $this->assertTrue($this->refusalNamesMaximum(
            fn () => new Creator($domain, $verifyOnly)
        ), 'the domain should be refused before the key is looked at');
    }

    /**
     * What the library itself signs still parses and still verifies, with an
     * ordinary domain and with one of the greatest length, so the bound is not
     * retrospective on anything real.
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
            $original = $creator->create('value');

            $parsed = Fixtures::parseBytes($original->asByteArray());

            $this->assertSame($domain, $parsed->domain);
            $this->assertTrue(
                $parsed->verifyWithCrypto($crypto),
                "parsed copy of '$domain' should verify"
            );
        }
    }
}
