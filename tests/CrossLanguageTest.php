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
use SwanCommunity\Owid\Owid;

/**
 * Verifies the cross language signed fixtures produced by other
 * implementations. These prove the verification path interoperates and the
 * DER to raw signature conversion is correct.
 */
final class CrossLanguageTest extends TestCase
{
    /**
     * @return array<string, array{0: string, 1: array<string, string>}>
     */
    public static function languages(): array
    {
        $cases = [];
        foreach (Fixtures::crossLanguage() as $name => $fixture) {
            $cases[$name] = [$name, $fixture];
        }
        return $cases;
    }

    /**
     * The simple payload OWID verifies with no others and exposes the ASCII
     * payload.
     *
     * @param array<string, string> $fixture
     *
     * @dataProvider languages
     */
    public function testSimpleVerifies(string $name, array $fixture): void
    {
        $owid = Owid::fromBase64($fixture['simple']);
        $this->assertSame('example', $owid->payloadAsString(), "$name simple payload");
        $this->assertTrue(
            $owid->verifyWithPublicKey($fixture['spki']),
            "$name simple should verify"
        );
    }

    /**
     * The utf8 payload OWID verifies and exposes the expected UTF-8 text.
     *
     * @param array<string, string> $fixture
     *
     * @dataProvider languages
     */
    public function testUtf8Verifies(string $name, array $fixture): void
    {
        $owid = Owid::fromBase64($fixture['utf8']);
        $this->assertSame(
            Fixtures::UTF8_PAYLOAD,
            $owid->payloadAsString(),
            "$name utf8 payload text"
        );
        $this->assertTrue(
            $owid->verifyWithPublicKey($fixture['spki']),
            "$name utf8 should verify"
        );
    }

    /**
     * The chain root verifies alone, the chain party verifies with the root as
     * the single other, and the party fails with no others.
     *
     * @param array<string, string> $fixture
     *
     * @dataProvider languages
     */
    public function testChainVerifies(string $name, array $fixture): void
    {
        $root = Owid::fromBase64($fixture['chain_root']);
        $party = Owid::fromBase64($fixture['chain_party']);
        $this->assertSame('root', $root->payloadAsString());
        $this->assertSame('party', $party->payloadAsString());
        $this->assertTrue(
            $root->verifyWithPublicKey($fixture['spki']),
            "$name chain root should verify alone"
        );
        $this->assertTrue(
            $party->verifyWithPublicKey($fixture['spki'], [$root]),
            "$name chain party should verify with the root"
        );
        $this->assertFalse(
            $party->verifyWithPublicKey($fixture['spki']),
            "$name chain party should fail with no others"
        );
    }

    /**
     * Each fixture with its last signature byte flipped fails to verify.
     *
     * @param array<string, string> $fixture
     *
     * @dataProvider languages
     */
    public function testTamperedFixturesFail(string $name, array $fixture): void
    {
        $root = Owid::fromBase64($fixture['chain_root']);
        foreach (['simple', 'utf8', 'chain_root'] as $key) {
            $owid = Owid::fromBase64($fixture[$key]);
            $tampered = self::flipLastByte($owid);
            $this->assertFalse(
                $tampered->verifyWithPublicKey($fixture['spki']),
                "$name $key with a flipped byte should fail"
            );
        }
        $party = Owid::fromBase64($fixture['chain_party']);
        $tamperedParty = self::flipLastByte($party);
        $this->assertFalse(
            $tamperedParty->verifyWithPublicKey($fixture['spki'], [$root]),
            "$name chain party with a flipped byte should fail"
        );
    }

    /**
     * Returns a copy of the OWID with its last serialized byte, a signature
     * byte, flipped.
     */
    private static function flipLastByte(Owid $owid): Owid
    {
        $bytes = $owid->asByteArray();
        $last = strlen($bytes) - 1;
        $bytes[$last] = chr(ord($bytes[$last]) ^ 0x01);
        return Owid::fromByteArray($bytes);
    }
}
