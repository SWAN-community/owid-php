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

/**
 * Plain PHP test runner that requires the source files directly and runs every
 * check without any external dependency. It is the fallback used when composer
 * and PHPUnit are not available. It prints PASS or FAIL per case and exits non
 * zero when any case fails. Run it with: php tests/run.php
 */

namespace SwanCommunity\Owid\Tests;

require __DIR__ . '/../src/OwidException.php';
require __DIR__ . '/../src/Version.php';
require __DIR__ . '/../src/Io.php';
require __DIR__ . '/../src/Crypto.php';
require __DIR__ . '/../src/Owid.php';
require __DIR__ . '/../src/Creator.php';
require __DIR__ . '/../src/Endpoints.php';
require __DIR__ . '/Fixtures.php';

use DateTimeImmutable;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Endpoints;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\Version;

/**
 * Minimal test harness. Each check is recorded with a name and a boolean
 * outcome, printed as it runs, and counted for the final summary.
 */
final class Runner
{
    private int $passed = 0;
    private int $failed = 0;

    public function check(string $name, bool $condition): void
    {
        if ($condition) {
            $this->passed += 1;
            echo "PASS  $name" . PHP_EOL;
        } else {
            $this->failed += 1;
            echo "FAIL  $name" . PHP_EOL;
        }
    }

    /**
     * Records a pass when the callable raises an OwidException, otherwise a
     * fail.
     */
    public function checkThrows(string $name, callable $callable): void
    {
        try {
            $callable();
            $this->check($name, false);
        } catch (OwidException $e) {
            $this->check($name, true);
        }
    }

    public function summary(): int
    {
        $total = $this->passed + $this->failed;
        echo PHP_EOL;
        echo "Ran $total checks, {$this->passed} passed, {$this->failed} failed." . PHP_EOL;
        return $this->failed === 0 ? 0 : 1;
    }
}

/**
 * Returns a copy of the OWID with its last serialized byte flipped.
 */
function flipLastByte(Owid $owid, array $others = []): Owid
{
    $bytes = $owid->asByteArray();
    $last = strlen($bytes) - 1;
    $bytes[$last] = chr(ord($bytes[$last]) ^ 0x01);
    return Owid::fromByteArray($bytes);
}

$runner = new Runner();

// A. Canonical wire format vectors round trip byte exact.
$vectors = [
    'creator' => Fixtures::CANONICAL_CREATOR,
    'supplier' => Fixtures::CANONICAL_SUPPLIER,
    'bad' => Fixtures::CANONICAL_BAD,
];
foreach ($vectors as $name => $value) {
    $bytes = base64_decode($value, true);
    $owid = Owid::fromByteArray($bytes);
    $runner->check(
        "canonical $name round trips byte exact",
        $bytes === $owid->asByteArray()
    );
}

$creator = Owid::fromBase64(Fixtures::CANONICAL_CREATOR);
$runner->check('creator domain is 51db.uk', $creator->domain === '51db.uk');
$runner->check('creator version is 2', $creator->version === Version::Version2);
$runner->check('creator payload length is 341', strlen($creator->payload) === 341);
$runner->check(
    'creator date is 2021-04-06T12:59Z',
    $creator->date->format('Y-m-d\TH:i\Z') === '2021-04-06T12:59Z'
);
$runner->check('creator first signature byte is 74', ord($creator->signature[0]) === 74);
$runner->check('creator last signature byte is 64', ord($creator->signature[63]) === 64);

$supplier = Owid::fromBase64(Fixtures::CANONICAL_SUPPLIER);
$runner->check('supplier payload printable is 0103', $supplier->payloadAsPrintable() === '0103');
$runner->check('supplier payload base64 is AQM=', $supplier->payloadAsBase64() === 'AQM=');

$runner->check(
    'bad vector parses',
    Owid::fromBase64(Fixtures::CANONICAL_BAD)->domain === 'badssp.swan-demo.uk'
);

// B. Cross language signed fixtures.
foreach (Fixtures::crossLanguage() as $lang => $fixture) {
    $spki = $fixture['spki'];

    $simple = Owid::fromBase64($fixture['simple']);
    $runner->check("$lang simple payload is example", $simple->payloadAsString() === 'example');
    $runner->check("$lang simple verifies", $simple->verifyWithPublicKey($spki));

    $utf8 = Owid::fromBase64($fixture['utf8']);
    $runner->check(
        "$lang utf8 payload text matches",
        $utf8->payloadAsString() === Fixtures::UTF8_PAYLOAD
    );
    $runner->check("$lang utf8 verifies", $utf8->verifyWithPublicKey($spki));

    $root = Owid::fromBase64($fixture['chain_root']);
    $party = Owid::fromBase64($fixture['chain_party']);
    $runner->check("$lang chain root verifies alone", $root->verifyWithPublicKey($spki));
    $runner->check(
        "$lang chain party verifies with root",
        $party->verifyWithPublicKey($spki, [$root])
    );
    $runner->check(
        "$lang chain party fails with no others",
        !$party->verifyWithPublicKey($spki)
    );

    foreach (['simple', 'utf8', 'chain_root'] as $key) {
        $tampered = flipLastByte(Owid::fromBase64($fixture[$key]));
        $runner->check(
            "$lang $key with flipped byte fails",
            !$tampered->verifyWithPublicKey($spki)
        );
    }
    $tamperedParty = flipLastByte($party);
    $runner->check(
        "$lang chain party with flipped byte fails",
        !$tamperedParty->verifyWithPublicKey($spki, [$root])
    );
}

// Sign and self verify, plus a tampered copy fails.
$crypto = Crypto::new();
$signer = new Creator('example.com', $crypto);
$signed = $signer->signString('Hello World');
$runner->check('signed OWID domain set by creator', $signed->domain === 'example.com');
$runner->check('signed OWID version is 3', $signed->version === Version::Version3);
$runner->check('signed OWID has 64 byte signature', strlen($signed->signature) === 64);
$runner->check('signed OWID verifies with crypto', $signed->verifyWithCrypto($crypto));
$copy = Owid::fromBase64($signed->asBase64());
$runner->check(
    'signed OWID verifies via public key after round trip',
    $copy->verifyWithPublicKey($crypto->publicKeyPem())
);
$tamperedLocal = flipLastByte($signed);
$runner->check('tampered local OWID fails', !$tamperedLocal->verifyWithCrypto($crypto));

// Local chain.
$localRoot = $signer->signString('root');
$localParty = new Owid();
$localParty->payload = 'party';
$signer->signWithOthers($localParty, [$localRoot]);
$runner->check('local chain party verifies with root', $localParty->verifyWithCrypto($crypto, [$localRoot]));
$runner->check('local chain party fails with no others', !$localParty->verifyWithCrypto($crypto));

// UTF-8 payload round trip.
$utf8Signed = $signer->signString(Fixtures::UTF8_PAYLOAD);
$utf8Copy = Owid::fromBase64($utf8Signed->asBase64());
$runner->check('utf8 payload round trips as text', $utf8Copy->payloadAsString() === Fixtures::UTF8_PAYLOAD);

// Empty PEM guards.
$runner->checkThrows('empty public PEM guard', fn () => Crypto::newVerifyOnly('   '));
$runner->checkThrows('empty private PEM guard', fn () => Crypto::newSignOnly(''));
$runner->checkThrows('invalid public PEM rejected', fn () => Crypto::newVerifyOnly('invalid'));
$runner->checkThrows('invalid private PEM rejected', fn () => Crypto::newSignOnly('invalid'));

// Crypto via PEM.
$pemSigner = Crypto::newSignOnly($crypto->privateKeyPem());
$pemVerifier = Crypto::newVerifyOnly($crypto->publicKeyPem());
$sig = $pemSigner->signByteArray('test');
$runner->check('sign via imported private key yields 64 bytes', strlen($sig) === 64);
$runner->check('verify via imported public key', $pemVerifier->verifyByteArray('test', $sig));
$runner->check('verify rejects other data', !$pemVerifier->verifyByteArray('other', $sig));
$runner->checkThrows(
    'verify rejects wrong length signature',
    fn () => $crypto->verifyByteArray('test', str_repeat("\x00", 63))
);
$runner->checkThrows(
    'verify only instance cannot sign',
    fn () => $pemVerifier->signByteArray('test')
);

// DER to raw round trips, including high bit and small value paths.
$rawHigh = str_repeat("\xFF", 32) . str_repeat("\x80", 32);
$runner->check(
    'DER round trip with high bit values',
    Crypto::derToRaw(Crypto::rawToDer($rawHigh)) === $rawHigh
);
$rawSmall = str_pad("\x01", 32, "\x00", STR_PAD_LEFT) . str_pad("\x02", 32, "\x00", STR_PAD_LEFT);
$runner->check(
    'DER round trip with small values',
    Crypto::derToRaw(Crypto::rawToDer($rawSmall)) === $rawSmall
);

// Io helpers.
$buffer = '';
Io::writeUint32($buffer, 0x0A242B01);
$runner->check('uint32 is little endian', $buffer === "\x01\x2B\x24\x0A");
$runner->check('uint32 round trips', (new Io($buffer))->readUint32() === 0x0A242B01);
$buffer = '';
Io::writeString($buffer, 'example.com');
$runner->check('string is null terminated', $buffer[strlen($buffer) - 1] === "\x00");
$runner->check('string round trips', (new Io($buffer))->readString() === 'example.com');
$buffer = '';
$now = new DateTimeImmutable('now');
Io::writeDate($buffer, $now, Version::Version2);
$runner->check('version 2 date uses four bytes', strlen($buffer) === 4);
$readMinutes = intdiv(
    (new Io($buffer))->readDate(Version::Version2)->getTimestamp() - Io::BASE_TIMESTAMP,
    60
);
$wantMinutes = intdiv($now->getTimestamp() - Io::BASE_TIMESTAMP, 60);
$runner->check('version 2 date round trips to the minute', $readMinutes === $wantMinutes);
$buffer = '';
$v1date = Io::baseDate()->modify('+12345 hours');
Io::writeDate($buffer, $v1date, Version::Version1);
$runner->check('version 1 date uses two bytes', strlen($buffer) === 2);
$runner->check(
    'version 1 date round trips to the hour',
    (new Io($buffer))->readDate(Version::Version1)->format('Y-m-d H:i') === $v1date->format('Y-m-d H:i')
);
$runner->checkThrows(
    'date before base date rejected',
    function () {
        $buffer = '';
        Io::writeDate($buffer, Io::baseDate()->modify('-1 minute'), Version::Version3);
    }
);
$runner->checkThrows(
    'string with null byte rejected',
    function () {
        $buffer = '';
        Io::writeString($buffer, "bad\x00value");
    }
);

// Empty marker.
$buffer = '';
Owid::emptyToBuffer($buffer);
$runner->check('empty marker is a single zero byte', $buffer === "\x00");
$runner->check('empty marker reads as empty version', Owid::fromByteArray($buffer)->version === Version::Empty);

// Creator behaviour.
$runner->checkThrows('empty domain rejected', fn () => new Creator('   ', Crypto::new()));
$runner->checkThrows(
    'verify only crypto rejected by creator',
    fn () => new Creator('example.com', $pemVerifier)
);
$fromConfig = Creator::fromConfiguration('example.com', $crypto->privateKeyPem());
$configOwid = $fromConfig->signString('value');
$runner->check(
    'creator from configuration signs verifiable OWID',
    $configOwid->verifyWithPublicKey($crypto->publicKeyPem())
);

// Endpoints.
$endpointCreator = new Creator('example.com', Crypto::new());
$body = Endpoints::creatorResponse($endpointCreator, 'Example Org', 'https://terms.example');
$runner->check('creator response has publicKeySPKI field', str_contains($body, 'publicKeySPKI'));
$parsed = json_decode($body, true);
$runner->check('creator response domain is example.com', $parsed['domain'] === 'example.com');
$runner->check('creator response name is Example Org', $parsed['name'] === 'Example Org');
$runner->check(
    'public key response returns PEM for spki',
    str_contains(Endpoints::publicKeyResponse($endpointCreator, 'spki'), 'BEGIN PUBLIC KEY')
);
$runner->check(
    'public key response returns PEM for pkcs',
    str_contains(Endpoints::publicKeyResponse($endpointCreator, 'pkcs'), 'BEGIN PUBLIC KEY')
);
$runner->checkThrows(
    'public key response rejects unknown format',
    fn () => Endpoints::publicKeyResponse($endpointCreator, 'other')
);
$runner->check(
    'creator path is correct',
    Endpoints::creatorPath(Version::Version3) === '/owid/api/v3/creator'
);
$runner->check(
    'public key path is correct',
    Endpoints::publicKeyPath(Version::Version3) === '/owid/api/v3/public-key'
);

// Payload length. The declared length is checked against the bytes present
// before anything is sized by it, and exactly the signature must follow.
function payloadEnvelope(int $declared, string $payload, string $signature): string
{
    $buffer = '';
    Io::writeByte($buffer, Version::Version3->asByte());
    Io::writeString($buffer, '51d.es');
    Io::writeUint32($buffer, 1000);
    Io::writeUint32($buffer, $declared);
    return $buffer . $payload . $signature;
}
$lengthPayload = str_repeat("\x5A", 37);
$lengthSignature = str_repeat("\x99", 64);
$runner->check(
    'matching payload length parses',
    Owid::fromByteArray(payloadEnvelope(37, $lengthPayload, $lengthSignature))->payload === $lengthPayload
);
$largeLengthPayload = str_repeat("\x5A", 1024 * 1024);
$runner->check(
    'matching one mebibyte payload parses',
    Owid::fromByteArray(payloadEnvelope(
        strlen($largeLengthPayload),
        $largeLengthPayload,
        $lengthSignature
    ))->payload === $largeLengthPayload
);
unset($largeLengthPayload);
$runner->check(
    'empty payload with signature parses',
    Owid::fromByteArray(payloadEnvelope(0, '', $lengthSignature))->payload === ''
);
foreach ([36, 38] as $declared) {
    $runner->checkThrows(
        "payload length $declared off by one refused",
        fn () => Owid::fromByteArray(payloadEnvelope($declared, $lengthPayload, $lengthSignature))
    );
}
$runner->checkThrows(
    'trailing byte after signature refused',
    fn () => Owid::fromByteArray(payloadEnvelope(37, $lengthPayload, $lengthSignature) . "\x00")
);
$runner->checkThrows(
    '63 byte signature refused',
    fn () => Owid::fromByteArray(payloadEnvelope(37, $lengthPayload, str_repeat("\x99", 63)))
);
foreach ([64 * 1024 * 1024, 0x7FFFFFFF, 0xFFFFFFFF] as $declared) {
    $refused = true;
    $start = hrtime(true);
    for ($attempt = 0; $attempt < 1000; $attempt++) {
        try {
            Owid::fromByteArray(payloadEnvelope($declared, '', ''));
            $refused = false;
        } catch (OwidException $e) {
        }
    }
    $elapsed = (hrtime(true) - $start) / 1e9;
    $runner->check(
        "declared length $declared refused 1000 times in under a second",
        $refused && $elapsed < 1.0
    );
}

// Domain length. The zero terminator is whatever the sender wrote, so the
// search for it stops at the greatest number of characters a domain name can
// hold rather than running to the end of the buffer.
function domainOfLength(int $length): string
{
    $labels = [];
    $remaining = $length;
    while ($remaining > 64) {
        $labels[] = str_repeat('a', 63);
        $remaining -= 64;
    }
    $labels[] = str_repeat('a', $remaining);
    return implode('.', $labels);
}
// The domain and its terminator are appended here rather than through
// Io::writeString because these checks build domains the write side now
// refuses, and the point of them is what the read side does with such bytes
// when they arrive from somewhere else.
function domainEnvelope(string $domain): string
{
    $buffer = '';
    Io::writeByte($buffer, Version::Version3->asByte());
    $buffer .= $domain . chr(0);
    Io::writeUint32($buffer, 1000);
    Io::writeUint32($buffer, 0);
    return $buffer . str_repeat("\x99", 64);
}
$maximumDomain = domainOfLength(OwidException::MAXIMUM_DOMAIN_LENGTH);
$maximumBytes = domainEnvelope($maximumDomain);
$maximumOwid = Owid::fromByteArray($maximumBytes);
$runner->check(
    'domain of the greatest length parses',
    $maximumOwid->domain === $maximumDomain
);
$runner->check(
    'domain of the greatest length round trips byte exact',
    $maximumOwid->asByteArray() === $maximumBytes
);
$runner->checkThrows(
    'domain one character over the greatest length refused',
    fn () => Owid::fromByteArray(
        domainEnvelope(domainOfLength(OwidException::MAXIMUM_DOMAIN_LENGTH + 1))
    )
);
$runner->checkThrows(
    'domain filling the bound with no terminator refused',
    fn () => Owid::fromByteArray(
        chr(Version::Version3->asByte()) .
        str_repeat('a', OwidException::MAXIMUM_DOMAIN_LENGTH)
    )
);
// The cost of a buffer with no terminator is timed over two buffers sixteen
// times apart, so the result does not depend on how fast the machine is. A
// search running to the end of the buffer costs sixteen times as much on the
// larger one, whereas a search stopping at the bound costs the same on both.
// The small allowance absorbs timer noise, because at the bound both runs
// take only a few thousandths of a second.
function timeDomainRefusals(string $bytes, int $attempts, bool &$refused): float
{
    $start = hrtime(true);
    for ($attempt = 0; $attempt < $attempts; $attempt++) {
        try {
            Owid::fromByteArray($bytes);
            $refused = false;
        } catch (OwidException $e) {
        }
    }
    return (hrtime(true) - $start) / 1e9;
}
$versionPrefix = chr(Version::Version3->asByte());
$smallUnterminated = $versionPrefix . str_repeat('a', 1024 * 1024);
$largeUnterminated = $versionPrefix . str_repeat('a', 16 * 1024 * 1024);
$refusedUnterminated = true;
$smallSeconds = timeDomainRefusals($smallUnterminated, 1000, $refusedUnterminated);
$largeSeconds = timeDomainRefusals($largeUnterminated, 1000, $refusedUnterminated);
$runner->check(
    'unterminated domain refused for a cost that does not grow with the buffer',
    $refusedUnterminated && $largeSeconds < 4 * $smallSeconds + 0.05
);
$runner->check(
    'unterminated domain refused 1000 times in under a second',
    $refusedUnterminated && $largeSeconds < 1.0
);
unset($smallUnterminated, $largeUnterminated);
$maximumCrypto = Crypto::new();
$maximumSigned = (new Creator($maximumDomain, $maximumCrypto))->signString('value');
$maximumParsed = Owid::fromByteArray($maximumSigned->asByteArray());
$runner->check(
    'signed OWID with the greatest length domain parses and verifies',
    $maximumParsed->domain === $maximumDomain &&
    $maximumParsed->verifyWithCrypto($maximumCrypto)
);

// The write is bounded as well, at the creator where the domain is supplied
// and again in the serialization, so this library cannot produce an OWID it
// would then refuse to read.
function domainRefusalNamesMaximum(callable $action): bool
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
$overLongDomain = domainOfLength(OwidException::MAXIMUM_DOMAIN_LENGTH + 1);
$runner->check(
    'creator refuses a domain over the greatest length, naming the maximum',
    domainRefusalNamesMaximum(
        fn () => new Creator($overLongDomain, $maximumCrypto)
    )
);
$runner->check(
    'creator from configuration refuses a domain over the greatest length',
    domainRefusalNamesMaximum(
        fn () => Creator::fromConfiguration(
            $overLongDomain,
            $maximumCrypto->privateKeyPem()
        )
    )
);
$overLongOwid = new Owid();
$overLongOwid->domain = $overLongDomain;
$overLongOwid->payload = 'value';
$overLongOwid->signature = str_repeat(chr(0x99), 64);
$runner->check(
    'serializing a domain over the greatest length is refused',
    domainRefusalNamesMaximum(fn () => $overLongOwid->asByteArray())
);
$runner->check(
    'building signing data for a domain over the greatest length is refused',
    domainRefusalNamesMaximum(fn () => $overLongOwid->dataForCrypto())
);
$atBoundOwid = new Owid();
$atBoundOwid->domain = $maximumDomain;
$atBoundOwid->payload = 'value';
$atBoundOwid->signature = str_repeat(chr(0x99), 64);
$runner->check(
    'serializing a domain of the greatest length parses back unchanged',
    Owid::fromByteArray($atBoundOwid->asByteArray())->domain === $maximumDomain
);
// The creator refuses the domain before it looks at the crypto instance, so
// an instance that can only verify still gives the domain message and not
// the key one, and nothing is ever signed with a domain that could not be
// read back.
$runner->check(
    'creator refuses the domain before looking at the crypto instance',
    domainRefusalNamesMaximum(
        fn () => new Creator(
            $overLongDomain,
            Crypto::newVerifyOnly($maximumCrypto->publicKeyPem())
        )
    )
);
// A domain arriving on another OWID covered by the signature is refused
// while the data to sign is being built, which is before the signing key is
// used, so the signature field is left holding what it held before.
$otherOwid = new Owid();
$otherOwid->domain = $overLongDomain;
$otherOwid->payload = 'other';
$otherOwid->signature = str_repeat(chr(0x11), 64);
$targetOwid = new Owid();
$targetOwid->payload = 'value';
$targetOwid->signature = str_repeat(chr(0x22), 64);
$runner->check(
    'over long domain on another OWID is refused when signing',
    domainRefusalNamesMaximum(
        fn () => (new Creator('51d.es', $maximumCrypto))
            ->signWithOthers($targetOwid, [$otherOwid])
    )
);
$runner->check(
    'signature is not calculated when the domain is refused',
    $targetOwid->signature === str_repeat(chr(0x22), 64)
);

exit($runner->summary());
