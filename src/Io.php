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

namespace SwanCommunity\Owid;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Low level read and write helpers for the OWID binary format. The format uses
 * little endian unsigned 32 bit integers, null terminated strings, and a fixed
 * 64 byte signature. Strings in PHP are byte arrays, so all buffers here are
 * plain strings holding raw bytes.
 */
final class Io
{
    /**
     * Unix timestamp of the base date 2020-01-01T00:00:00 UTC. The date and
     * time information is stored as hours or minutes after this date.
     */
    public const BASE_TIMESTAMP = 1577836800;

    /**
     * Returns the base date for OWIDs as a UTC immutable date and time.
     */
    public static function baseDate(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . self::BASE_TIMESTAMP);
    }

    /**
     * Sequential reader over a byte buffer. PHP strings are used as the byte
     * buffer because each element accessed by offset is a single byte.
     */
    private string $buffer;
    private int $position;

    public function __construct(string $buffer)
    {
        $this->buffer = $buffer;
        $this->position = 0;
    }

    /**
     * Reads a single byte and returns its unsigned integer value.
     *
     * @throws OwidException when the buffer has no more bytes.
     */
    public function readByte(): int
    {
        if ($this->position >= strlen($this->buffer)) {
            throw OwidException::unexpectedEndOfBuffer();
        }
        $value = ord($this->buffer[$this->position]);
        $this->position += 1;
        return $value;
    }

    /**
     * Reads the requested number of raw bytes from the buffer.
     *
     * @throws OwidException when the buffer is too short.
     */
    public function readBytes(int $count): string
    {
        if ($count < 0 || $this->position + $count > strlen($this->buffer)) {
            throw OwidException::unexpectedEndOfBuffer();
        }
        $value = substr($this->buffer, $this->position, $count);
        $this->position += $count;
        return $value;
    }

    /**
     * Reads bytes until the null terminator and returns them as a string. The
     * terminator is consumed but not returned.
     *
     * @throws OwidException when no terminator is found.
     */
    public function readString(): string
    {
        $terminator = strpos($this->buffer, "\0", $this->position);
        if ($terminator === false) {
            throw OwidException::unexpectedEndOfBuffer();
        }
        $value = substr(
            $this->buffer,
            $this->position,
            $terminator - $this->position
        );
        $this->position = $terminator + 1;
        return $value;
    }

    /**
     * Reads an unsigned 32 bit little endian integer.
     *
     * @throws OwidException when the buffer is too short.
     */
    public function readUint32(): int
    {
        $bytes = $this->readBytes(4);
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('V', $bytes);
        return $unpacked[1];
    }

    /**
     * Reads a byte array prefixed with its length as an unsigned 32 bit
     * integer.
     *
     * @throws OwidException when the buffer is too short.
     */
    public function readByteArray(): string
    {
        $count = $this->readUint32();
        return $this->readBytes($count);
    }

    /**
     * Reads the fixed length signature.
     *
     * @throws OwidException when the buffer is too short.
     */
    public function readSignature(): string
    {
        return $this->readBytes(OwidException::SIGNATURE_LENGTH);
    }

    /**
     * Reads the date using the encoding associated with the version.
     *
     * @throws OwidException when the version has no date encoding or the
     *                       buffer is too short.
     */
    public function readDate(Version $version): DateTimeImmutable
    {
        switch ($version) {
            case Version::Version1:
                $bytes = $this->readBytes(2);
                /** @var array{1: int} $unpacked */
                $unpacked = unpack('n', $bytes);
                $hours = $unpacked[1];
                return self::baseDate()->modify('+' . $hours . ' hours');
            case Version::Version2:
            case Version::Version3:
                $minutes = $this->readUint32();
                return self::baseDate()->modify('+' . $minutes . ' minutes');
            default:
                throw OwidException::unsupportedVersion($version->asByte());
        }
    }

    /**
     * Appends a single byte, given as an unsigned integer, to the buffer.
     */
    public static function writeByte(string &$buffer, int $value): void
    {
        $buffer .= chr($value & 0xFF);
    }

    /**
     * Writes the string followed by the null terminator. The string must not
     * contain a null character as that would conflict with the terminator.
     *
     * @throws OwidException when the value contains a null byte.
     */
    public static function writeString(string &$buffer, string $value): void
    {
        if (strpos($value, "\0") !== false) {
            throw OwidException::invalidDomain($value);
        }
        $buffer .= $value . "\0";
    }

    /**
     * Writes an unsigned 32 bit little endian integer.
     */
    public static function writeUint32(string &$buffer, int $value): void
    {
        $buffer .= pack('V', $value);
    }

    /**
     * Writes a byte array prefixed with its length as an unsigned 32 bit
     * integer.
     *
     * @throws OwidException when the value is longer than the prefix allows.
     */
    public static function writeByteArray(string &$buffer, string $value): void
    {
        $length = strlen($value);
        if ($length > 0xFFFFFFFF) {
            throw OwidException::payloadTooLarge($length);
        }
        self::writeUint32($buffer, $length);
        $buffer .= $value;
    }

    /**
     * Writes the fixed length signature, validating the length.
     *
     * @throws OwidException when the signature is not the required length.
     */
    public static function writeSignature(string &$buffer, string $value): void
    {
        if (strlen($value) !== OwidException::SIGNATURE_LENGTH) {
            throw OwidException::invalidSignatureLength(strlen($value));
        }
        $buffer .= $value;
    }

    /**
     * Writes the date using the encoding associated with the version. The
     * value is truncated to the minute, or the hour for version 1, by the
     * integer arithmetic.
     *
     * @throws OwidException when the version has no date encoding or the date
     *                       falls outside the range the encoding allows.
     */
    public static function writeDate(
        string &$buffer,
        DateTimeImmutable $date,
        Version $version
    ): void {
        $elapsed = $date->getTimestamp() - self::BASE_TIMESTAMP;
        switch ($version) {
            case Version::Version1:
                $hours = intdiv($elapsed, 3600);
                if ($hours < 0 || $hours > 0xFFFF) {
                    throw OwidException::dateOutOfRange();
                }
                $buffer .= pack('n', $hours);
                return;
            case Version::Version2:
            case Version::Version3:
                $minutes = intdiv($elapsed, 60);
                if ($minutes < 0 || $minutes > 0xFFFFFFFF) {
                    throw OwidException::dateOutOfRange();
                }
                self::writeUint32($buffer, $minutes);
                return;
            default:
                throw OwidException::unsupportedVersion($version->asByte());
        }
    }
}
