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

/**
 * OWID structure which can be used as a node in a tree.
 *
 * An OWID records that the processor operating the domain handled the payload,
 * and any other OWIDs covered by the signature, at the date and time given.
 * Once signed it is immutable. Any change to the fields will cause
 * verification to fail.
 *
 * The payload and signature are held as raw byte strings because PHP strings
 * are byte arrays.
 */
final class Owid
{
    /** The byte version of the OWID. */
    public Version $version;

    /** Domain associated with the creator. */
    public string $domain;

    /** The date and time to the nearest minute in UTC of the creation. */
    public DateTimeImmutable $date;

    /** Raw bytes that form the payload. */
    public string $payload;

    /**
     * Signature for this OWID and any others provided when signing. Generated
     * by the Creator instance and held as 64 raw bytes once signed.
     */
    public string $signature;

    /**
     * Creates a new unsigned OWID with the domain, date, and payload provided
     * and the current version. With no arguments an empty OWID at the current
     * time is created.
     */
    public function __construct(
        string $domain = '',
        ?DateTimeImmutable $date = null,
        string $payload = ''
    ) {
        $this->version = Version::default();
        $this->domain = $domain;
        $this->date = $date ?? new DateTimeImmutable('now');
        $this->payload = $payload;
        $this->signature = '';
    }

    /**
     * Creates an OWID from a base 64 encoded string. Input with or without the
     * trailing padding is accepted.
     *
     * @throws OwidException when the string is not valid base 64 or the bytes
     *                       do not form a valid OWID.
     */
    public static function fromBase64(string $value): self
    {
        return self::fromByteArray(self::base64Decode($value));
    }

    /**
     * Creates an OWID from its binary form.
     *
     * @throws OwidException when the version is unknown or the buffer is too
     *                       short for the remaining fields.
     */
    public static function fromByteArray(string $buffer): self
    {
        return self::fromReader(new Io($buffer));
    }

    /**
     * Creates an OWID by reading the next fields from the reader.
     *
     * @throws OwidException when the version is unknown or the buffer is too
     *                       short.
     */
    public static function fromReader(Io $reader): self
    {
        $version = Version::fromByte($reader->readByte());
        $owid = new self();
        $owid->version = $version;
        if ($version === Version::Empty) {
            return $owid;
        }
        $owid->domain = $reader->readString();
        $owid->date = $reader->readDate($version);
        $owid->payload = $reader->readByteArray();
        $owid->signature = $reader->readSignature();
        return $owid;
    }

    /**
     * Returns the OWID as a byte array.
     *
     * @throws OwidException when the OWID has not been signed or the fields
     *                       can not be encoded.
     */
    public function asByteArray(): string
    {
        $buffer = '';
        $this->toBuffer($buffer);
        return $buffer;
    }

    /**
     * Returns the OWID as a base 64 encoded string with padding.
     *
     * @throws OwidException when the OWID can not be serialized.
     */
    public function asBase64(): string
    {
        return base64_encode($this->asByteArray());
    }

    /**
     * Appends the OWID, including the signature, to the buffer provided.
     *
     * @throws OwidException when the OWID can not be serialized.
     */
    public function toBuffer(string &$buffer): void
    {
        $this->toBufferNoSignature($buffer);
        Io::writeSignature($buffer, $this->signature);
    }

    /**
     * Appends an empty OWID marker to the buffer. Used to indicate optional
     * OWIDs in byte arrays.
     */
    public static function emptyToBuffer(string &$buffer): void
    {
        Io::writeByte($buffer, Version::Empty->asByte());
    }

    /**
     * Appends the fields other than the signature to the buffer. This is the
     * data over which the signature is calculated.
     *
     * @throws OwidException when the fields can not be encoded.
     */
    public function toBufferNoSignature(string &$buffer): void
    {
        Io::writeByte($buffer, $this->version->asByte());
        Io::writeString($buffer, $this->domain);
        Io::writeDate($buffer, $this->date, $this->version);
        Io::writeByteArray($buffer, $this->payload);
    }

    /**
     * Builds the byte array used for signing and verification. Contains the
     * fields of this OWID without the signature, followed by the complete byte
     * form of each of the others in the order provided.
     *
     * @param array<int, Owid> $others
     *
     * @throws OwidException when the fields can not be encoded.
     */
    public function dataForCrypto(array $others = []): string
    {
        $buffer = '';
        $this->toBufferNoSignature($buffer);
        foreach ($others as $other) {
            $other->toBuffer($buffer);
        }
        return $buffer;
    }

    /**
     * The payload interpreted as a string of raw bytes. The payload is treated
     * as UTF-8 text by callers, but no transformation is applied here.
     */
    public function payloadAsString(): string
    {
        return $this->payload;
    }

    /**
     * The payload as lower case hexadecimal for display purposes, with no
     * separator. For example the bytes 0x01 0x03 become "0103".
     */
    public function payloadAsPrintable(): string
    {
        return bin2hex($this->payload);
    }

    /**
     * The payload as a base 64 encoded string with padding.
     */
    public function payloadAsBase64(): string
    {
        return base64_encode($this->payload);
    }

    /**
     * Returns the number of complete minutes that have elapsed since the OWID
     * was created. The granularity is to the nearest minute.
     */
    public function ageMinutes(): int
    {
        $now = new DateTimeImmutable('now');
        return intdiv($now->getTimestamp() - $this->date->getTimestamp(), 60);
    }

    /**
     * Verifies this OWID, and any others that were included when it was
     * signed, using the crypto instance provided. Pass an empty array for
     * others when the OWID was signed on its own.
     *
     * @param array<int, Owid> $others
     *
     * @throws OwidException when the crypto instance can not verify or the
     *                       fields can not be encoded.
     */
    public function verifyWithCrypto(Crypto $crypto, array $others = []): bool
    {
        $data = $this->dataForCrypto($others);
        return $crypto->verifyByteArray($data, $this->signature);
    }

    /**
     * Verifies this OWID, and any others that were included when it was
     * signed, using the public key in SPKI PEM form provided.
     *
     * @param array<int, Owid> $others
     *
     * @throws OwidException when the PEM is not a valid public key or the
     *                       fields can not be encoded.
     */
    public function verifyWithPublicKey(string $publicPem, array $others = []): bool
    {
        $crypto = Crypto::newVerifyOnly($publicPem);
        return $this->verifyWithCrypto($crypto, $others);
    }

    /**
     * Returns the OWID as a base 64 string, the same as asBase64. Used when an
     * OWID is converted to a string.
     *
     * @throws OwidException when the OWID can not be serialized.
     */
    public function __toString(): string
    {
        return $this->asBase64();
    }

    /**
     * Decodes a standard alphabet base 64 string, accepting input with or
     * without the trailing padding.
     *
     * @throws OwidException when the string is not valid base 64.
     */
    private static function base64Decode(string $value): string
    {
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw OwidException::base64();
        }
        return $decoded;
    }
}
