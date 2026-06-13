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
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\OwidException;

/**
 * Tests the crypto operations, the DER to raw signature conversion, and the
 * empty PEM guards.
 */
final class CryptoTest extends TestCase
{
    private const TEST_PAYLOAD = 'test';

    /**
     * Keys exported to PEM and imported into sign only and verify only
     * instances produce signatures that verify.
     */
    public function testSignAndVerifyViaPem(): void
    {
        $crypto = Crypto::new();
        $privatePem = $crypto->privateKeyPem();
        $publicPem = $crypto->publicKeyPem();
        $signer = Crypto::newSignOnly($privatePem);
        $verifier = Crypto::newVerifyOnly($publicPem);
        $signature = $signer->signByteArray(self::TEST_PAYLOAD);
        $this->assertSame(64, strlen($signature), 'signature should be 64 raw bytes');
        $this->assertTrue(
            $verifier->verifyByteArray(self::TEST_PAYLOAD, $signature),
            'signature should verify'
        );
    }

    /**
     * A signature over one payload does not verify against a different
     * payload.
     */
    public function testSignatureDoesNotVerifyOtherData(): void
    {
        $crypto = Crypto::new();
        $signature = $crypto->signByteArray(self::TEST_PAYLOAD);
        $this->assertFalse(
            $crypto->verifyByteArray('different', $signature),
            'signature over other data should not verify'
        );
    }

    /**
     * A freshly generated instance can verify its own signature, exercising
     * the derived public key.
     */
    public function testGeneratedInstanceVerifiesOwnSignature(): void
    {
        $crypto = Crypto::new();
        $this->assertTrue($crypto->canSign());
        $this->assertTrue($crypto->canVerify());
        $signature = $crypto->signByteArray(self::TEST_PAYLOAD);
        $this->assertTrue($crypto->verifyByteArray(self::TEST_PAYLOAD, $signature));
    }

    /**
     * An invalid public PEM is rejected.
     */
    public function testInvalidPublicPem(): void
    {
        $this->expectException(OwidException::class);
        Crypto::newVerifyOnly('invalid');
    }

    /**
     * An invalid private PEM is rejected.
     */
    public function testInvalidPrivatePem(): void
    {
        $this->expectException(OwidException::class);
        Crypto::newSignOnly('invalid');
    }

    /**
     * An empty public PEM is rejected by the explicit guard with a clear
     * message.
     */
    public function testEmptyPublicPemGuard(): void
    {
        try {
            Crypto::newVerifyOnly('   ');
            $this->fail('empty public PEM should raise');
        } catch (OwidException $e) {
            $this->assertStringContainsString('public key PEM is empty', $e->getMessage());
        }
    }

    /**
     * An empty private PEM is rejected by the explicit guard with a clear
     * message.
     */
    public function testEmptyPrivatePemGuard(): void
    {
        try {
            Crypto::newSignOnly('');
            $this->fail('empty private PEM should raise');
        } catch (OwidException $e) {
            $this->assertStringContainsString('private key PEM is empty', $e->getMessage());
        }
    }

    /**
     * A verify only instance can not sign.
     */
    public function testVerifyOnlyCannotSign(): void
    {
        $crypto = Crypto::new();
        $verifier = Crypto::newVerifyOnly($crypto->publicKeyPem());
        $this->assertFalse($verifier->canSign());
        $this->expectException(OwidException::class);
        $verifier->signByteArray(self::TEST_PAYLOAD);
    }

    /**
     * A verify only instance can not export a private key.
     */
    public function testVerifyOnlyCannotExportPrivateKey(): void
    {
        $crypto = Crypto::new();
        $verifier = Crypto::newVerifyOnly($crypto->publicKeyPem());
        $this->expectException(OwidException::class);
        $verifier->privateKeyPem();
    }

    /**
     * A signature of the wrong length is rejected with an error rather than
     * returning false.
     */
    public function testWrongLengthSignatureRejected(): void
    {
        $crypto = Crypto::new();
        $this->expectException(OwidException::class);
        $crypto->verifyByteArray(self::TEST_PAYLOAD, str_repeat("\x00", 63));
    }

    /**
     * The exported public PEM is in SPKI form.
     */
    public function testPublicKeyIsSpki(): void
    {
        $crypto = Crypto::new();
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $crypto->publicKeyPem());
    }

    /**
     * Converting a raw signature to DER and back to raw is the identity for a
     * real signature.
     */
    public function testDerRawRoundTrip(): void
    {
        $crypto = Crypto::new();
        $raw = $crypto->signByteArray(self::TEST_PAYLOAD);
        $der = Crypto::rawToDer($raw);
        $this->assertSame(0x30, ord($der[0]), 'DER starts with a SEQUENCE tag');
        $backToRaw = Crypto::derToRaw($der);
        $this->assertSame(bin2hex($raw), bin2hex($backToRaw), 'should round trip');
    }

    /**
     * The DER encoder adds a sign byte when the high bit of r or s is set so
     * the value reads as positive, and the decoder strips it again. A value
     * with the high bit set in its first byte exercises this path.
     */
    public function testDerHandlesHighBitValues(): void
    {
        $r = str_repeat("\xFF", 32);
        $s = str_repeat("\x80", 32);
        $raw = $r . $s;
        $der = Crypto::rawToDer($raw);
        $back = Crypto::derToRaw($der);
        $this->assertSame(bin2hex($raw), bin2hex($back));
    }

    /**
     * Small r and s values are left padded to 32 bytes on the way back to raw.
     */
    public function testDerPadsSmallValues(): void
    {
        $r = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x02", 32, "\x00", STR_PAD_LEFT);
        $raw = $r . $s;
        $der = Crypto::rawToDer($raw);
        $back = Crypto::derToRaw($der);
        $this->assertSame(64, strlen($back));
        $this->assertSame(bin2hex($raw), bin2hex($back));
    }
}
