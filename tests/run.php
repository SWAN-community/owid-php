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
require __DIR__ . '/../src/ParseStatus.php';
require __DIR__ . '/../src/SignatureStatus.php';
require __DIR__ . '/../src/ParseResult.php';
require __DIR__ . '/../src/Crypto.php';
require __DIR__ . '/../src/Owid.php';
require __DIR__ . '/../src/Creator.php';
require __DIR__ . '/../src/Endpoints.php';
require __DIR__ . '/../src/PublicKeyFetchException.php';
require __DIR__ . '/../src/DatedPublicKey.php';
require __DIR__ . '/../src/PublicKeySchedule.php';
require __DIR__ . '/../src/PublicKeyFetch.php';
require __DIR__ . '/Fixtures.php';
require __DIR__ . '/KeyFixtures.php';

use DateTimeImmutable;
use Error;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Endpoints;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\ParseStatus;
use SwanCommunity\Owid\SignatureStatus;
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
     * fail. Used for the write and configuration side, where a fault is a
     * fault in the program rather than data arriving from outside.
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

    /**
     * Records a pass when reading the bytes reports the status given, hands
     * back no value, and raises nothing.
     */
    public function checkRefused(
        string $name,
        string $bytes,
        ParseStatus $expected
    ): void {
        $result = Owid::tryFromByteArray($bytes);
        $this->check(
            $name,
            !$result->ok &&
            $result->owid === null &&
            $result->status === $expected
        );
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
 * Reads a value the runner expects to be a well formed OWID, and stops the run
 * with the reason when it is not.
 */
function parse(string $value): Owid
{
    $result = Owid::tryFromBase64($value);
    if (!$result->ok) {
        echo 'FAIL  fixture did not read: ' . $result->status->value . PHP_EOL;
        exit(1);
    }
    return $result->owid;
}

/**
 * Reads bytes the runner expects to be one whole OWID, and stops the run with
 * the reason when they are not.
 */
function parseBytes(string $bytes): Owid
{
    $result = Owid::tryFromByteArray($bytes);
    if (!$result->ok) {
        echo 'FAIL  bytes did not read: ' . $result->status->value . PHP_EOL;
        exit(1);
    }
    return $result->owid;
}

/**
 * Returns a copy of the OWID with its last serialized byte flipped, read back
 * from the bytes because that is how tampering reaches a verifier.
 */
function flipLastByte(Owid $owid): Owid
{
    $bytes = $owid->asByteArray();
    $last = strlen($bytes) - 1;
    $bytes[$last] = chr(ord($bytes[$last]) ^ 0x01);
    return parseBytes($bytes);
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
    $owid = parseBytes($bytes);
    $runner->check(
        "canonical $name round trips byte exact",
        $bytes === $owid->asByteArray()
    );
}

$creatorVector = parse(Fixtures::CANONICAL_CREATOR);
$runner->check('creator domain is 51db.uk', $creatorVector->domain === '51db.uk');
$runner->check('creator version is 2', $creatorVector->version === Version::Version2);
$runner->check('creator payload length is 341', strlen($creatorVector->payload) === 341);
$runner->check(
    'creator date is 2021-04-06T12:59Z',
    $creatorVector->date->format('Y-m-d\TH:i\Z') === '2021-04-06T12:59Z'
);
$runner->check('creator first signature byte is 74', ord($creatorVector->signature[0]) === 74);
$runner->check('creator last signature byte is 64', ord($creatorVector->signature[63]) === 64);

$supplier = parse(Fixtures::CANONICAL_SUPPLIER);
$runner->check('supplier payload printable is 0103', $supplier->payloadAsPrintable() === '0103');
$runner->check('supplier payload base64 is AQM=', $supplier->payloadAsBase64() === 'AQM=');

$runner->check(
    'bad vector reads',
    parse(Fixtures::CANONICAL_BAD)->domain === 'badssp.swan-demo.uk'
);

// B. Cross language signed fixtures.
foreach (Fixtures::crossLanguage() as $lang => $fixture) {
    $spki = $fixture['spki'];

    $simple = parse($fixture['simple']);
    $runner->check("$lang simple payload is example", $simple->payloadAsString() === 'example');
    $runner->check("$lang simple verifies", $simple->verifyWithPublicKey($spki));
    $runner->check(
        "$lang simple reports a valid signature",
        $simple->signatureStatus($spki) === SignatureStatus::SignatureValid
    );

    $utf8 = parse($fixture['utf8']);
    $runner->check(
        "$lang utf8 payload text matches",
        $utf8->payloadAsString() === Fixtures::UTF8_PAYLOAD
    );
    $runner->check("$lang utf8 verifies", $utf8->verifyWithPublicKey($spki));

    $root = parse($fixture['chain_root']);
    $party = parse($fixture['chain_party']);
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
        $tampered = flipLastByte(parse($fixture[$key]));
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

// Create and self verify, plus a tampered copy fails.
$crypto = Crypto::new();
$signer = new Creator('example.com', $crypto);
$signed = $signer->create('Hello World');
$runner->check('created OWID domain set by creator', $signed->domain === 'example.com');
$runner->check('created OWID version is 3', $signed->version === Version::Version3);
$runner->check('created OWID has 64 byte signature', strlen($signed->signature) === 64);
$runner->check('created OWID verifies with crypto', $signed->verifyWithCrypto($crypto));
$copy = parse($signed->asBase64());
$runner->check(
    'created OWID verifies via public key after round trip',
    $copy->verifyWithPublicKey($crypto->publicKeyPem())
);
$tamperedLocal = flipLastByte($signed);
$runner->check('tampered local OWID fails', !$tamperedLocal->verifyWithCrypto($crypto));

// A caller cannot build an OWID, and cannot change one.
$constructorIsPrivate = (new \ReflectionClass(Owid::class))->getConstructor()->isPrivate();
$runner->check('the OWID constructor is private', $constructorIsPrivate);
$reboundRefused = false;
try {
    $signed->payload = 'other';
} catch (Error $e) {
    $reboundRefused = str_contains($e->getMessage(), 'readonly');
}
$runner->check('an OWID field cannot be rebound', $reboundRefused);
$payloadCopy = $signed->payload;
$payloadCopy[0] = 'z';
$runner->check(
    'writing into a returned payload does not alter the OWID',
    $signed->payload === 'Hello World'
);
$runner->check(
    'the creator offers no way to sign an existing OWID',
    !method_exists(Creator::class, 'sign') &&
    !method_exists(Creator::class, 'signWithOthers') &&
    !method_exists(Creator::class, 'signString') &&
    !method_exists(Creator::class, 'signBytes')
);

// Local chain.
$localRoot = $signer->create('root');
$localParty = $signer->create('party', [$localRoot]);
$runner->check(
    'local chain party verifies with root',
    $localParty->verifyWithCrypto($crypto, [$localRoot])
);
$runner->check('local chain party fails with no others', !$localParty->verifyWithCrypto($crypto));

// UTF-8 payload round trip.
$utf8Signed = $signer->create(Fixtures::UTF8_PAYLOAD);
$utf8Copy = parse($utf8Signed->asBase64());
$runner->check('utf8 payload round trips as text', $utf8Copy->payloadAsString() === Fixtures::UTF8_PAYLOAD);

// Reading answers rather than raising, with the same three facts every time.
$goodResult = Owid::tryFromByteArray($signed->asByteArray());
$runner->check(
    'a successful read reports it worked, a value and Parsed',
    $goodResult->ok &&
    $goodResult->owid !== null &&
    $goodResult->status === ParseStatus::Parsed
);
$runner->check(
    'absent input is missing input',
    Owid::tryFromBase64(null)->status === ParseStatus::MissingInput &&
    Owid::tryFromBase64('')->status === ParseStatus::MissingInput &&
    Owid::tryFromByteArray(null)->status === ParseStatus::MissingInput
);
$runner->check(
    'input that is not text is the wrong sort of input',
    Owid::tryFromBase64(['a'])->status === ParseStatus::InvalidInputType &&
    Owid::tryFromBase64(5)->status === ParseStatus::InvalidInputType
);
$runner->check(
    'invalid base 64 is reported',
    Owid::tryFromBase64('not base 64 at all!!')->status === ParseStatus::InvalidBase64
);
$runner->checkRefused(
    'an unknown version byte is reported',
    "\x09rest",
    ParseStatus::UnsupportedVersion
);
$runner->checkRefused(
    'a buffer stopping inside the envelope ends early',
    substr($signed->asByteArray(), 0, 8),
    ParseStatus::UnexpectedEnd
);
$runner->checkRefused(
    'a trailing byte is a byte count mismatch',
    $signed->asByteArray() . "\x00",
    ParseStatus::ByteCountMismatch
);
$badSignatureBytes = $signed->asByteArray();
$badSignatureBytes[strlen($badSignatureBytes) - 1] = chr(
    ord($badSignatureBytes[strlen($badSignatureBytes) - 1]) ^ 0xFF
);
$badSignatureResult = Owid::tryFromByteArray($badSignatureBytes);
$runner->check(
    'a valid structure with a bad signature reads and then fails to verify',
    $badSignatureResult->ok && !$badSignatureResult->owid->verifyWithCrypto($crypto)
);
$runner->check(
    'a key that cannot be read is not an invalid signature',
    $signed->signatureStatus('not a pem') === SignatureStatus::InvalidKey
);

// Empty PEM guards.
$runner->checkThrows('empty public PEM guard', fn () => Crypto::newVerifyOnly('   '));
$runner->checkThrows('empty private PEM guard', fn () => Crypto::newSignOnly(''));
$runner->checkThrows('invalid public PEM rejected', fn () => Crypto::newVerifyOnly('invalid'));
$runner->checkThrows('invalid private PEM rejected', fn () => Crypto::newSignOnly('invalid'));
$runner->check('unreadable PEM answers with null', Crypto::tryVerifyOnly('invalid') === null);

// Crypto via PEM.
$pemSigner = Crypto::newSignOnly($crypto->privateKeyPem());
$pemVerifier = Crypto::newVerifyOnly($crypto->publicKeyPem());
$sig = $pemSigner->signByteArray('test');
$runner->check('sign via imported private key yields 64 bytes', strlen($sig) === 64);
$runner->check('verify via imported public key', $pemVerifier->verifyByteArray('test', $sig));
$runner->check('verify rejects other data', !$pemVerifier->verifyByteArray('other', $sig));
$runner->check(
    'a signature of the wrong length is not a signature that does not match',
    $pemVerifier->signatureStatus('test', str_repeat("\x00", 63)) ===
        SignatureStatus::InvalidSignatureLength
);
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

/**
 * A version 3 envelope carrying the domain, date and payload given, followed
 * by the signature bytes given, built with the write helpers so that what is
 * written can be read back the way a caller reads it.
 */
function envelope(
    string $domain,
    DateTimeImmutable $date,
    string $payload,
    string $signature
): string {
    $buffer = '';
    Io::writeByte($buffer, Version::Version3->asByte());
    Io::writeString($buffer, $domain);
    Io::writeDate($buffer, $date, Version::Version3);
    Io::writeByteArray($buffer, $payload);
    return $buffer . $signature;
}

// Io write helpers, read back through a complete envelope.
$buffer = '';
Io::writeUint32($buffer, 0x0A242B01);
$runner->check('uint32 is little endian', $buffer === "\x01\x2B\x24\x0A");
$buffer = '';
Io::writeString($buffer, 'example.com');
$runner->check('string is null terminated', $buffer[strlen($buffer) - 1] === "\x00");
$now = new DateTimeImmutable('now');
$fullSignature = str_repeat("\x99", 64);
$written = parseBytes(envelope('example.com', $now, "\x01\x02", $fullSignature));
$runner->check('written domain reads back', $written->domain === 'example.com');
$runner->check('written payload reads back', $written->payload === "\x01\x02");
$runner->check(
    'written date reads back to the minute',
    intdiv($written->date->getTimestamp() - Io::BASE_TIMESTAMP, 60) ===
    intdiv($now->getTimestamp() - Io::BASE_TIMESTAMP, 60)
);
$buffer = '';
Io::writeDate($buffer, $now, Version::Version2);
$runner->check('version 2 date uses four bytes', strlen($buffer) === 4);
$buffer = '';
$v1date = Io::baseDate()->modify('+12345 hours');
Io::writeDate($buffer, $v1date, Version::Version1);
$runner->check('version 1 date uses two bytes', strlen($buffer) === 2);
$v1buffer = '';
Io::writeByte($v1buffer, Version::Version1->asByte());
Io::writeString($v1buffer, 'example.com');
Io::writeDate($v1buffer, $v1date, Version::Version1);
Io::writeByteArray($v1buffer, '');
$v1owid = parseBytes($v1buffer . $fullSignature);
$runner->check(
    'version 1 date reads back to the hour',
    $v1owid->date->format('Y-m-d H:i') === $v1date->format('Y-m-d H:i')
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
$runner->checkThrows(
    'signature of the wrong length rejected on write',
    function () {
        $buffer = '';
        Io::writeSignature($buffer, str_repeat("\x99", 63));
    }
);

// Empty marker.
$buffer = '';
Owid::emptyToBuffer($buffer);
$runner->check('empty marker is a single zero byte', $buffer === " ");
// The marker for a node that is absent is not an OWID, so no value is handed
// back on either contract, and it is not an unknown version either, because
// version 0 is supported and meaningful. Its one byte is counted so that a
// caller walking a run of frames steps over the absent node.
$markerWhole = Owid::tryFromByteArray($buffer);
$runner->check(
    'the marker for an absent node hands back no OWID as a whole buffer',
    !$markerWhole->ok &&
    $markerWhole->owid === null &&
    $markerWhole->status === ParseStatus::AbsentNode
);
$markerFrame = Owid::tryFromFrame($buffer . $signed->asByteArray());
$runner->check(
    'the marker for an absent node is reported and counted when framed',
    !$markerFrame->ok &&
    $markerFrame->owid === null &&
    $markerFrame->status === ParseStatus::AbsentNode &&
    $markerFrame->consumed === 1
);
$afterMarker = Owid::tryFromFrame($buffer . $signed->asByteArray(), 1);
$runner->check(
    'a frame walk steps over an absent node and reads the next OWID',
    $afterMarker->ok && $afterMarker->owid->payloadAsString() === 'Hello World'
);
// A framed envelope that stops early is data that stopped, not a declaration
// disagreeing with data that is all present, because the bytes may still be
// arriving and waiting for more is a different answer from giving up.
$shortFrame = substr($signed->asByteArray(), 0, strlen($signed->asByteArray()) - 1);
$runner->check(
    'a short frame ends early rather than disagreeing',
    Owid::tryFromFrame($shortFrame)->status === ParseStatus::UnexpectedEnd &&
    Owid::tryFromByteArray($shortFrame)->status === ParseStatus::ByteCountMismatch
);
$runner->check(
    'a buffer of no bytes is missing input',
    Owid::tryFromByteArray('')->status === ParseStatus::MissingInput &&
    Owid::tryFromBase64("



")->status === ParseStatus::MissingInput
);

// Creator behaviour.
$runner->checkThrows('empty domain rejected', fn () => new Creator('   ', Crypto::new()));
$runner->checkThrows(
    'verify only crypto rejected by creator',
    fn () => new Creator('example.com', $pemVerifier)
);
$fromConfig = Creator::fromConfiguration('example.com', $crypto->privateKeyPem());
$configOwid = $fromConfig->create('value');
$runner->check(
    'creator from configuration creates a verifiable OWID',
    $configOwid->verifyWithPublicKey($crypto->publicKeyPem())
);

// Endpoints.
$endpointCreator = new Creator('example.com', Crypto::new());
$body = Endpoints::creatorResponse($endpointCreator, 'Example Org', 'https://terms.example');
$runner->check('creator response has publicKeySPKI field', str_contains($body, 'publicKeySPKI'));
$parsedBody = json_decode($body, true);
$runner->check('creator response domain is example.com', $parsedBody['domain'] === 'example.com');
$runner->check('creator response name is Example Org', $parsedBody['name'] === 'Example Org');
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
    'matching payload length reads',
    parseBytes(payloadEnvelope(37, $lengthPayload, $lengthSignature))->payload === $lengthPayload
);
$largeLengthPayload = str_repeat("\x5A", 1024 * 1024);
$runner->check(
    'matching one mebibyte payload reads',
    parseBytes(payloadEnvelope(
        strlen($largeLengthPayload),
        $largeLengthPayload,
        $lengthSignature
    ))->payload === $largeLengthPayload
);
unset($largeLengthPayload);
$runner->check(
    'empty payload with signature reads',
    parseBytes(payloadEnvelope(0, '', $lengthSignature))->payload === ''
);
foreach ([36, 38] as $declared) {
    $runner->checkRefused(
        "payload length $declared off by one refused",
        payloadEnvelope($declared, $lengthPayload, $lengthSignature),
        ParseStatus::ByteCountMismatch
    );
}
$runner->checkRefused(
    'trailing byte after signature refused',
    payloadEnvelope(37, $lengthPayload, $lengthSignature) . "\x00",
    ParseStatus::ByteCountMismatch
);
$runner->checkRefused(
    '63 byte signature refused',
    payloadEnvelope(37, $lengthPayload, str_repeat("\x99", 63)),
    ParseStatus::ByteCountMismatch
);
foreach ([64 * 1024 * 1024, 0x7FFFFFFF, 0xFFFFFFFF] as $declared) {
    $refused = true;
    $bytes = payloadEnvelope($declared, '', '');
    $start = hrtime(true);
    for ($attempt = 0; $attempt < 1000; $attempt++) {
        $result = Owid::tryFromByteArray($bytes);
        if ($result->ok || $result->status !== ParseStatus::ByteCountMismatch) {
            $refused = false;
        }
    }
    $elapsed = (hrtime(true) - $start) / 1e9;
    $runner->check(
        "declared length $declared refused 1000 times in under a second",
        $refused && $elapsed < 1.0
    );
}

// The framed reader leaves what follows for the next read.
$framed = payloadEnvelope(37, $lengthPayload, $lengthSignature) .
    payloadEnvelope(0, '', $lengthSignature);
$firstFrame = Owid::tryFromFrame($framed);
$secondFrame = Owid::tryFromFrame($framed, $firstFrame->consumed);
$runner->check(
    'the framed reader reads one envelope and leaves the next',
    $firstFrame->ok &&
    $secondFrame->ok &&
    $firstFrame->consumed + $secondFrame->consumed === strlen($framed)
);

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
// Io::writeString because these checks build domains the write side refuses,
// and the point of them is what the read side does with such bytes when they
// arrive from somewhere else.
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
$maximumOwid = parseBytes($maximumBytes);
$runner->check(
    'domain of the greatest length reads',
    $maximumOwid->domain === $maximumDomain
);
$runner->check(
    'domain of the greatest length round trips byte exact',
    $maximumOwid->asByteArray() === $maximumBytes
);
$runner->checkRefused(
    'domain one character over the greatest length refused',
    domainEnvelope(domainOfLength(OwidException::MAXIMUM_DOMAIN_LENGTH + 1)),
    ParseStatus::InvalidDomainEncoding
);
$runner->checkRefused(
    'domain filling the bound with no terminator refused',
    chr(Version::Version3->asByte()) .
    str_repeat('a', OwidException::MAXIMUM_DOMAIN_LENGTH),
    ParseStatus::UnexpectedEnd
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
        $result = Owid::tryFromByteArray($bytes);
        if ($result->ok || $result->status !== ParseStatus::InvalidDomainEncoding) {
            $refused = false;
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
$maximumSigned = (new Creator($maximumDomain, $maximumCrypto))->create('value');
$maximumParsed = parseBytes($maximumSigned->asByteArray());
$runner->check(
    'created OWID with the greatest length domain reads and verifies',
    $maximumParsed->domain === $maximumDomain &&
    $maximumParsed->verifyWithCrypto($maximumCrypto)
);

// The write is bounded as well, at the creator where the domain is supplied
// and again in the write helper, so this library cannot produce bytes it would
// then refuse to read.
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
$runner->check(
    'writing a domain over the greatest length is refused',
    domainRefusalNamesMaximum(function () use ($overLongDomain) {
        $buffer = '';
        Io::writeString($buffer, $overLongDomain);
    })
);
// The creator refuses the domain before it looks at the crypto instance, so an
// instance that can only verify still gives the domain message and not the key
// one, and nothing is ever signed with a domain that could not be read back.
$runner->check(
    'creator refuses the domain before looking at the crypto instance',
    domainRefusalNamesMaximum(
        fn () => new Creator(
            $overLongDomain,
            Crypto::newVerifyOnly($maximumCrypto->publicKeyPem())
        )
    )
);

// The dated key fetch and the published schedule, against the genuine
// identifier the cloud issued on 4 September 2026 and the thirty keys the
// creator published.
$published = KeyFixtures::schedule();
$genuine = KeyFixtures::identifier();
$chosenKey = $published->keyFor($genuine);
$runner->check(
    'the schedule chooses the week of 31 August 2026 for the genuine identifier',
    $chosenKey !== null
        && $chosenKey->startsAt == KeyFixtures::weekOfTheIdentifier()
);
$runner->check(
    'the schedule verifies the genuine identifier',
    $published->signatureStatus($genuine)
        === \SwanCommunity\Owid\SignatureStatus::SignatureValid
);
$runner->check(
    'the last key of the schedule is not the key that signed the identifier',
    $published->last() !== $chosenKey
);
$runner->check(
    'the fetch URL names the version, the minute and the well known path',
    \SwanCommunity\Owid\PublicKeyFetch::publicKeyUrl($genuine, 'https')
        === 'https://51d.es/owid/api/v3/public-key?date=3510720&format=pkcs'
);
\SwanCommunity\Owid\PublicKeyFetch::clearCache();
$served = [];
$serving = function (string $url, float $timeout) use ($chosenKey, &$served): array {
    $served[] = $url;
    return [200, \SwanCommunity\Owid\Endpoints::publicKeyAnswer($chosenKey->publicKeyPem, null, null, null)];
};
$runner->check(
    "the fetch verifies through a transport of the caller's own",
    \SwanCommunity\Owid\PublicKeyFetch::signatureStatus($genuine, 'https', [], $serving)
        === \SwanCommunity\Owid\SignatureStatus::SignatureValid
);
$runner->check(
    'a key already fetched is not asked for again',
    \SwanCommunity\Owid\PublicKeyFetch::verify($genuine, 'https', [], $serving)
        && count($served) === 1
);
\SwanCommunity\Owid\PublicKeyFetch::clearCache();
$runner->check(
    'a key the creator cannot serve is unavailable rather than invalid',
    \SwanCommunity\Owid\PublicKeyFetch::signatureStatus(
        $genuine,
        'https',
        [],
        fn (string $url, float $timeout): array => [404, '']
    ) === \SwanCommunity\Owid\SignatureStatus::KeyUnavailable
);
\SwanCommunity\Owid\PublicKeyFetch::clearCache();
$answered = \SwanCommunity\Owid\Endpoints::publicKeyResponseAt(
    $published,
    'pkcs',
    (string) KeyFixtures::IDENTIFIER_MINUTES,
    new \DateTimeImmutable('2026-09-14T00:00:00Z')
);
$runner->check(
    'the end point answers the key in force at the date asked',
    $answered[0] === 200
        && json_decode($answered[1], true)['publicKeySPKI'] === $chosenKey->publicKeyPem
        && json_decode($answered[1], true)['validFrom'] === '2026-08-31T00:00:00Z'
        && json_decode($answered[1], true)['validTo'] === '2026-09-07T00:00:00Z'
);
$runner->check(
    'the end point answers 404 before the schedule begins',
    \SwanCommunity\Owid\Endpoints::publicKeyResponseAt($published, 'pkcs', '0')[0] === 404
);

exit($runner->summary());
