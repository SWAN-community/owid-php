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
 * Tests the low level binary read and write helpers.
 */
final class IoTest extends TestCase
{
    /**
     * A date written and read with the version 2 encoding keeps the same
     * minute count.
     */
    public function testDateRoundTripVersion2(): void
    {
        $date = new DateTimeImmutable('now');
        $buffer = '';
        Io::writeDate($buffer, $date, Version::Version2);
        $this->assertSame(4, strlen($buffer), 'version 2 uses four bytes');
        $result = (new Io($buffer))->readDate(Version::Version2);
        $expected = intdiv($date->getTimestamp() - Io::BASE_TIMESTAMP, 60);
        $actual = intdiv($result->getTimestamp() - Io::BASE_TIMESTAMP, 60);
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
        $result = (new Io($buffer))->readDate(Version::Version1);
        $this->assertSame(
            $date->format('Y-m-d H:i'),
            $result->format('Y-m-d H:i'),
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
        $this->assertSame("\x00", $buffer[strlen($buffer) - 1], 'should be null terminated');
        $result = (new Io($buffer))->readString();
        $this->assertSame('example.com', $result);
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
        $this->assertSame(0x0A242B01, (new Io($buffer))->readUint32(), 'should round trip');
    }

    /**
     * A byte array is written with its length prefix and read back whole.
     */
    public function testByteArrayRoundTrip(): void
    {
        $payload = "\x01\x02\x03\x04\x05";
        $buffer = '';
        Io::writeByteArray($buffer, $payload);
        $reader = new Io($buffer);
        $this->assertSame($payload, $reader->readByteArray());
    }

    /**
     * Reading past the end of the buffer raises an error.
     */
    public function testReadPastEndRejected(): void
    {
        $reader = new Io("\x01");
        $reader->readByte();
        $this->expectException(OwidException::class);
        $reader->readByte();
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
