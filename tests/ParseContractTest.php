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

use Error;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionProperty;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\ParseStatus;
use SwanCommunity\Owid\SignatureStatus;

/**
 * What the reading and creation surfaces promise, tested as a contract.
 *
 * Two promises are kept here. The first is that reading external data always
 * answers rather than raising, and answers with the same three facts, being
 * whether it worked, the value only when it did, and a named reason either
 * way. The second is that an OWID arrives only by being read or by a creator
 * signing one, so no caller can hold a half made or altered identifier.
 */
final class ParseContractTest extends TestCase
{
    private static function creator(): Creator
    {
        return new Creator('example.com', Crypto::new());
    }

    /**
     * A successful read reports that it worked, hands back the OWID, and names
     * the reason as Parsed.
     */
    public function testSuccessReportsAllThreeFacts(): void
    {
        $owid = self::creator()->create("\x01\x02\x03");

        $result = Owid::tryFromByteArray($owid->asByteArray());

        $this->assertTrue($result->ok);
        $this->assertInstanceOf(Owid::class, $result->owid);
        $this->assertSame(ParseStatus::Parsed, $result->status);
        $this->assertSame("\x01\x02\x03", $result->owid->payload);
    }

    /**
     * The base 64 surface reports the same three facts, so a caller reading an
     * encoded identifier is not handed a different contract.
     */
    public function testBase64SuccessReportsAllThreeFacts(): void
    {
        $owid = self::creator()->create('value');

        $result = Owid::tryFromBase64($owid->asBase64());

        $this->assertTrue($result->ok);
        $this->assertInstanceOf(Owid::class, $result->owid);
        $this->assertSame(ParseStatus::Parsed, $result->status);
        $this->assertSame('value', $result->owid->payloadAsString());
    }

    /**
     * Base 64 with and without the trailing padding both read, because an
     * encoded OWID is carried both ways and refusing the unpadded form would
     * reject a normal way of holding one.
     */
    public function testPaddedAndUnpaddedBase64BothRead(): void
    {
        $padded = self::creator()->create('value')->asBase64();
        $unpadded = rtrim($padded, '=');

        $this->assertTrue(Owid::tryFromBase64($padded)->ok);
        $this->assertTrue(Owid::tryFromBase64($unpadded)->ok);
    }

    /**
     * An empty payload reads. Having nothing to say is allowed, because the
     * payload is what the creator had to say and an OWID carrying nothing is
     * still an OWID.
     */
    public function testEmptyPayloadParses(): void
    {
        $owid = self::creator()->create('');

        $result = Owid::tryFromByteArray($owid->asByteArray());

        $this->assertTrue($result->ok, $result->status->value);
        $this->assertSame('', $result->owid->payload);
    }

    /**
     * A megabyte reads. The format's limit is the wire format's, and how much
     * an application will accept is that application's policy rather than
     * something this library decides for it.
     */
    public function testOneMebibytePayloadParses(): void
    {
        $payload = str_repeat("\x5A", 1024 * 1024);
        $owid = self::creator()->create($payload);

        $result = Owid::tryFromByteArray($owid->asByteArray());

        $this->assertTrue($result->ok, $result->status->value);
        $this->assertSame(strlen($payload), strlen($result->owid->payload));
    }

    /**
     * Absent input is reported as nothing having been supplied, on both
     * surfaces, and nothing is handed back.
     */
    public function testAbsentInputIsMissingInput(): void
    {
        foreach ([null, ''] as $value) {
            foreach (['tryFromBase64', 'tryFromByteArray'] as $method) {
                $result = Owid::$method($value);
                $this->assertFalse($result->ok);
                $this->assertNull($result->owid);
                $this->assertSame(ParseStatus::MissingInput, $result->status);
            }
        }
    }

    /**
     * Input that is not text at all is reported as the wrong sort of input
     * rather than raising a type error. A repeated query parameter with
     * brackets reaches a PHP application as an array, so a caller passing on
     * what it was given is not necessarily passing on a string.
     */
    public function testNonStringInputIsInvalidInputType(): void
    {
        foreach ([['a'], 5, 1.5, true, new \stdClass()] as $value) {
            $result = Owid::tryFromBase64($value);
            $this->assertFalse($result->ok);
            $this->assertNull($result->owid);
            $this->assertSame(ParseStatus::InvalidInputType, $result->status);
        }
    }

    /**
     * Invalid base 64 is reported and not raised.
     */
    public function testInvalidBase64IsReported(): void
    {
        foreach (['not base 64 at all!!', '####', 'AAAAA'] as $value) {
            $result = Owid::tryFromBase64($value);
            $this->assertFalse($result->ok, "'$value' should not read");
            $this->assertNull($result->owid);
            $this->assertSame(ParseStatus::InvalidBase64, $result->status);
        }
    }

    /**
     * A version byte this implementation does not know is reported, and no
     * fields after it are read.
     */
    public function testUnsupportedVersionIsReported(): void
    {
        $bytes = self::creator()->create('x')->asByteArray();
        $bytes[0] = chr(9);

        $result = Owid::tryFromByteArray($bytes);

        $this->assertFalse($result->ok);
        $this->assertNull($result->owid);
        $this->assertSame(ParseStatus::UnsupportedVersion, $result->status);
    }

    /**
     * One byte after a complete envelope is a disagreement between the
     * declared payload and the bytes that follow it, because the declared
     * payload no longer leaves exactly the signature the version requires.
     */
    public function testTrailingByteIsByteCountMismatch(): void
    {
        $bytes = self::creator()->create('x')->asByteArray() . "\x00";

        $result = Owid::tryFromByteArray($bytes);

        $this->assertFalse($result->ok);
        $this->assertNull($result->owid);
        $this->assertSame(ParseStatus::ByteCountMismatch, $result->status);
    }

    /**
     * Data that stops inside a field, before the payload length is even read,
     * is data that ended early. Each cut is inside a different field.
     */
    public function testDataStoppingInsideTheEnvelopeEndsEarly(): void
    {
        $bytes = self::creator()->create('x')->asByteArray();
        // Inside the domain, inside the date, and inside the payload length,
        // which are the three fields read before the count check.
        foreach ([5, strlen('example.com') + 3, strlen('example.com') + 8] as $cut) {
            $result = Owid::tryFromByteArray(substr($bytes, 0, $cut));

            $this->assertFalse($result->ok, "a cut at $cut should not read");
            $this->assertNull($result->owid);
            $this->assertSame(
                ParseStatus::UnexpectedEnd,
                $result->status,
                "a cut at $cut should end early"
            );
        }
    }

    /**
     * An OWID cannot be built by a caller. The constructor is private, which
     * the engine enforces, so the two routes in the documentation are the only
     * two there are. Without this an unsigned OWID could be handed to code
     * that cannot tell the difference.
     */
    public function testConstructionFromOutsideIsImpossible(): void
    {
        $constructor = (new ReflectionClass(Owid::class))->getConstructor();
        $this->assertNotNull($constructor);
        $this->assertTrue(
            $constructor->isPrivate(),
            'the constructor must not be reachable from outside'
        );

        $this->expectException(Error::class);
        /** @phpstan-ignore-next-line the point of the test is that this fails */
        new Owid();
    }

    /**
     * No field can be set or rebound from outside. Every declared property is
     * read only, which the engine enforces, so an OWID always says what was
     * read or signed.
     */
    public function testNoFieldCanBeRebound(): void
    {
        $owid = self::creator()->create('abc');
        $properties = (new ReflectionClass(Owid::class))->getProperties();
        $this->assertNotEmpty($properties);
        foreach ($properties as $property) {
            $this->assertTrue(
                $property->isReadOnly(),
                $property->getName() . ' must be read only'
            );
        }

        foreach (['version', 'domain', 'date', 'payload', 'signature'] as $field) {
            try {
                $owid->$field = null;
                $this->fail("$field should not be assignable");
            } catch (Error $e) {
                $this->assertStringContainsString('readonly', $e->getMessage());
            }
        }
    }

    /**
     * Writing into the payload a caller was handed does not alter the OWID. A
     * PHP string is a value rather than a reference, so what the caller holds
     * is its own copy and there is nothing to defend against by copying again.
     */
    public function testWritingIntoAReturnedPayloadDoesNotAlterTheOwid(): void
    {
        $owid = self::creator()->create('abc');

        $payload = $owid->payload;
        $payload[0] = 'z';
        $signature = $owid->signature;
        $signature[0] = 'z';

        $this->assertSame('abc', $owid->payload);
        $this->assertSame('zbc', $payload);
        $this->assertNotSame($signature, $owid->signature);
    }

    /**
     * A created OWID always carries a signature, so there is no state in which
     * one exists unsigned.
     */
    public function testCreatedOwidIsAlwaysSigned(): void
    {
        $crypto = Crypto::new();
        $owid = (new Creator('example.com', $crypto))->create('value');

        $this->assertSame(64, strlen($owid->signature));
        $this->assertTrue($owid->verifyWithCrypto($crypto));
    }

    /**
     * A structurally valid identifier whose signature does not match reads,
     * and then fails verification. Two questions with two answers, because
     * whether the bytes form an OWID and whether the signature is genuine are
     * asked and answered separately.
     */
    public function testValidStructureWithBadSignatureParsesThenFailsToVerify(): void
    {
        $crypto = Crypto::new();
        $owid = (new Creator('example.com', $crypto))->create("\x04\x05\x06");
        $bytes = $owid->asByteArray();
        $last = strlen($bytes) - 1;
        $bytes[$last] = chr(ord($bytes[$last]) ^ 0xFF);

        $result = Owid::tryFromByteArray($bytes);

        $this->assertTrue(
            $result->ok,
            'flipping a signature byte leaves the envelope readable'
        );
        $this->assertSame(ParseStatus::Parsed, $result->status);
        $this->assertFalse($result->owid->verifyWithCrypto($crypto));
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            $result->owid->signatureStatusWithCrypto($crypto)
        );
    }

    /**
     * A key that cannot be read is reported as a fault in the key and never as
     * a signature that does not match, because the identifier may be perfectly
     * good and only the key material wrong. On 30 August 2026 the key end
     * points served PEM a strict parser rejects, and every verification
     * against it failed while the keys and the identifiers were both fine.
     */
    public function testUnreadableKeyIsNotAnInvalidSignature(): void
    {
        $owid = self::creator()->create('value');

        foreach (['', '   ', 'not a pem', "-----BEGIN PUBLIC KEY-----\nx\n"] as $pem) {
            $status = $owid->signatureStatus($pem);

            $this->assertSame(
                SignatureStatus::InvalidKey,
                $status,
                'unreadable key material must not read as a forgery'
            );
        }
    }

    /**
     * Nothing is verified during a failed read. There is no value to check a
     * signature on, and the reading code names neither the crypto class nor
     * any openssl call, so a failure cannot reach one.
     */
    public function testNoVerificationHappensDuringAFailedParse(): void
    {
        $bytes = self::creator()->create('x')->asByteArray();
        $bytes[0] = chr(9);

        $result = Owid::tryFromByteArray($bytes);

        $this->assertFalse($result->ok);
        $this->assertNull(
            $result->owid,
            'no value means nothing exists on which to check a signature'
        );

        $method = new ReflectionMethod(Owid::class, 'parse');
        $source = file(__DIR__ . '/../src/Owid.php');
        $body = implode('', array_slice(
            $source,
            $method->getStartLine() - 1,
            $method->getEndLine() - $method->getStartLine() + 1
        ));
        foreach (['Crypto', 'openssl', 'verify'] as $forbidden) {
            $this->assertStringNotContainsStringIgnoringCase(
                $forbidden,
                $body,
                "reading must not reach $forbidden"
            );
        }
    }

    /**
     * This library never fetches a key, so no read can cause a request. The
     * source is scanned for the ways PHP reaches the network, which is a
     * stronger statement than any single test of the parse path.
     */
    public function testNothingInTheLibraryReachesTheNetwork(): void
    {
        $calls = [
            'curl_init',
            'file_get_contents',
            'fopen',
            'fsockopen',
            'stream_socket_client',
            'stream_context_create',
        ];
        foreach (glob(__DIR__ . '/../src/*.php') as $file) {
            $source = file_get_contents($file);
            foreach ($calls as $call) {
                $this->assertStringNotContainsString(
                    $call . '(',
                    $source,
                    basename($file) . " must not call $call"
                );
            }
        }
    }

    /**
     * The properties a caller reads are the ones the parser filled, so the
     * result of a read cannot be quietly changed into saying something else.
     */
    public function testResultFieldsAreReadOnly(): void
    {
        $result = Owid::tryFromByteArray(self::creator()->create('x')->asByteArray());

        foreach (['ok', 'owid', 'status', 'consumed'] as $field) {
            try {
                $result->$field = null;
                $this->fail("$field should not be assignable");
            } catch (Error $e) {
                $this->assertStringContainsString('readonly', $e->getMessage());
            }
        }
    }
}
