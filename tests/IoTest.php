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

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\Version;

/**
 * Tests the low level write helpers and the base date the format counts from.
 *
 * Each field is written and then read back through a complete envelope,
 * because reading is done by the parser in Owid rather than by a helper here,
 * and reading one field on its own is not something a caller can do.
 */
final class IoTest extends TestCase
{
    /** The length of the fixed tail every valid OWID ends with. */
    private const SIGNATURE_LENGTH = 64;

    /**
     * An envelope of the version given, carrying the domain, date and payload
     * given, so a written field can be read back the way a caller reads one.
     */
    private static function envelope(
        Version $version,
        string $domain,
        DateTimeImmutable $date,
        string $payload
    ): string {
        $buffer = '';
        Io::writeByte($buffer, $version->asByte());
        Io::writeString($buffer, $domain);
        Io::writeDate($buffer, $date, $version);
        Io::writeByteArray($buffer, $payload);
        return $buffer . str_repeat("\x99", self::SIGNATURE_LENGTH);
    }

    /**
     * A date written and read with the version 3 encoding keeps the same
     * minute count in four bytes.
     */
    public function testDateRoundTripVersion3(): void
    {
        $date = new DateTimeImmutable('now');
        $buffer = '';
        Io::writeDate($buffer, $date, Version::Version3);
        $this->assertSame(4, strlen($buffer), 'version 3 uses four bytes');

        $owid = Fixtures::parseBytes(
            self::envelope(Version::Version3, 'example.com', $date, '')
        );

        $expected = intdiv($date->getTimestamp() - Io::BASE_TIMESTAMP, 60);
        $actual = intdiv($owid->date->getTimestamp() - Io::BASE_TIMESTAMP, 60);
        $this->assertSame($expected, $actual, 'should keep the same minute count');
    }

    /**
     * A date written and read with the version 1 encoding keeps hour
     * granularity in two bytes.
     */
    public function testDateRoundTripVersion1(): void
    {
        $date = Io::baseDate()->modify('+12345 hours');
        $buffer = '';
        Io::writeDate($buffer, $date, Version::Version1);
        $this->assertSame(2, strlen($buffer), 'version 1 uses two bytes');

        $owid = Fixtures::parseBytes(
            self::envelope(Version::Version1, 'example.com', $date, '')
        );

        $this->assertSame(
            $date->format('Y-m-d H:i'),
            $owid->date->format('Y-m-d H:i'),
            'should keep hour granularity'
        );
    }

    /**
     * Dates before the base date can not be encoded.
     */
    public function testDateBeforeBaseRejected(): void
    {
        $date = Io::baseDate()->modify('-1 minute');
        $buffer = '';
        $this->expectException(OwidException::class);
        Io::writeDate($buffer, $date, Version::Version3);
    }

    /**
     * Strings are written with a null terminator and read back without it.
     */
    public function testStringRoundTrip(): void
    {
        $buffer = '';
        Io::writeString($buffer, 'example.com');
        $this->assertSame(
            "\x00",
            $buffer[strlen($buffer) - 1],
            'should be null terminated'
        );

        $owid = Fixtures::parseBytes(self::envelope(
            Version::Version3,
            'example.com',
            new DateTimeImmutable('now'),
            ''
        ));

        $this->assertSame('example.com', $owid->domain);
    }

    /**
     * A string holding a null byte can not be written.
     */
    public function testStringWithNullRejected(): void
    {
        $buffer = '';
        $this->expectException(OwidException::class);
        Io::writeString($buffer, "bad\x00value");
    }

    /**
     * Unsigned 32 bit integers use little endian byte order.
     */
    public function testUint32LittleEndian(): void
    {
        $buffer = '';
        Io::writeUint32($buffer, 0x0A242B01);
        $this->assertSame("\x01\x2B\x24\x0A", $buffer, 'should be little endian');
    }

    /**
     * A byte array is written with its length prefix and read back whole.
     */
    public function testByteArrayRoundTrip(): void
    {
        $payload = "\x01\x02\x03\x04\x05";
        $buffer = '';
        Io::writeByteArray($buffer, $payload);
        $this->assertSame("\x05\x00\x00\x00" . $payload, $buffer);

        $owid = Fixtures::parseBytes(self::envelope(
            Version::Version3,
            'example.com',
            new DateTimeImmutable('now'),
            $payload
        ));

        $this->assertSame($payload, $owid->payload);
    }

    /**
     * A signature that is not the fixed length can not be written, so the
     * library cannot produce an envelope whose tail it would then refuse.
     */
    public function testSignatureLengthEnforcedOnWrite(): void
    {
        $buffer = '';
        $this->expectException(OwidException::class);
        Io::writeSignature($buffer, str_repeat("\x99", 63));
    }

    /**
     * The base date is the documented timestamp.
     */
    public function testBaseDate(): void
    {
        $this->assertSame(1577836800, Io::BASE_TIMESTAMP);
        $this->assertSame(
            '2020-01-01T00:00:00+00:00',
            Io::baseDate()->format('c')
        );
    }
}
