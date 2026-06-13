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

use Exception;

/**
 * The single exception type raised when creating, reading, signing, or
 * verifying OWIDs. Each named constructor produces a clear message describing
 * what went wrong.
 */
final class OwidException extends Exception
{
    /**
     * The length in bytes of a valid OWID signature.
     */
    public const SIGNATURE_LENGTH = 64;

    /**
     * The version byte is not one supported by this implementation.
     */
    public static function unsupportedVersion(int $version): self
    {
        return new self("OWID version '$version' not supported");
    }

    /**
     * The signature is not exactly the required number of bytes.
     */
    public static function invalidSignatureLength(int $length): self
    {
        $expected = self::SIGNATURE_LENGTH;
        return new self(
            "signature length '$length' not compatible with '$expected' " .
            "OWID signature length"
        );
    }

    /**
     * The buffer ended before all the expected fields were read.
     */
    public static function unexpectedEndOfBuffer(): self
    {
        return new self('buffer ended before the OWID was complete');
    }

    /**
     * The base 64 string could not be decoded.
     */
    public static function base64(): self
    {
        return new self('base 64 decoding failed because the input is not valid');
    }

    /**
     * The domain is empty, or contains a null character which would conflict
     * with the null terminated string encoding.
     */
    public static function invalidDomain(string $domain): self
    {
        return new self("domain '$domain' is not valid");
    }

    /**
     * The date can not be represented in the encoding used by the version.
     */
    public static function dateOutOfRange(): self
    {
        return new self(
            'date can not be stored in the encoding for the OWID version'
        );
    }

    /**
     * The payload is larger than the unsigned 32 bit length prefix allows.
     */
    public static function payloadTooLarge(int $length): self
    {
        return new self(
            "payload length '$length' exceeds the unsigned 32 bit limit"
        );
    }

    /**
     * A key could not be imported, exported, or used. The message contains the
     * underlying detail.
     */
    public static function key(string $detail): self
    {
        return new self("key operation failed because $detail");
    }

    /**
     * The crypto instance can not be used for the operation requested. For
     * example, an attempt to sign with a verify only instance.
     */
    public static function keyMissing(string $operation): self
    {
        return new self("instance of Crypto cannot be used to $operation");
    }

    /**
     * The format parameter for the public key end point was not one of the
     * valid values "spki" or "pkcs".
     */
    public static function invalidKeyFormat(string $format): self
    {
        return new self(
            "format parameter 'spki' or 'pkcs' must be provided, " .
            "received '$format'"
        );
    }
}
