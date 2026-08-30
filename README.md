![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) for PHP

Simple cryptographically auditable identifiers and processors implemented in
PHP. This library creates, signs, serializes, and verifies OWIDs.

## Overview

An OWID records that the entity operating a domain captured or generated a
payload at a date and time, with an ECDSA signature over the OWID and any
other OWIDs it was signed together with. OWIDs chain to form verifiable trees.
The cryptography is ECDSA on the NIST P-256 curve (also known as secp256r1 or
prime256v1) with the SHA-256 hash.

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more
about the concepts before looking into this implementation.

## Scope of this implementation

This library provides the core of OWID with no network access and no external
runtime dependencies. It uses the PHP openssl extension for the cryptography
and the mbstring and json extensions for text and end point helpers.

It covers:

- Reading and writing the OWID binary wire format, byte exact across versions.
- Signing and verifying with ECDSA P-256 and SHA-256.
- Building and verifying chains of OWIDs.
- Framework agnostic helpers for the well known end points a creator hosts.

Versions 1 and 2 of the wire format are deprecated and supported for reading
existing data only. New OWIDs use version 3.

Fetching a creator public key over HTTP is out of scope. The
`verifyWithPublicKey` and `signatureStatus` methods accept a public key PEM
that the caller has already obtained, so any HTTP client can supply it.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain carries no
length before it either, so the protocol alone is not an application input
limit for the complete envelope.

This library checks that the declared payload length agrees with the bytes
present before it extracts the payload, and reports the disagreement as
`ParseStatus::ByteCountMismatch`. A large declaration without the
corresponding bytes is malformed and is rejected without allocating the
declared size. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The domain is read the same way. Because nothing declares its length, the
search for its terminator stops at the greatest number of characters a domain
name can hold, which RFC 1035 section 2.3.4 fixes for the presentation form
this library stores. A domain with no terminator, or one longer than a domain
name may be, is rejected for a cost set by that maximum rather than by the
length of the buffer.

The same maximum binds the write, so this library cannot produce an OWID it
would then refuse to read. A `Creator` refuses a domain longer than the maximum
when the domain is supplied, which is the earliest point the caller can be
told, and the write helpers refuse one as well, so a caller writing the format
with them directly is held to the same bound.

The in-memory APIs remain subject to PHP string, platform, address-space and
available-memory limits. Applications accepting untrusted OWIDs must choose
limits suitable for their use case and enforce them before buffering the
binary form or decoding Base64. An implementation capacity failure or an
application policy rejection is distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope, and
allow for the domain and other OWID fields as well as the payload. After a
successful read, `strlen($result->owid->payload)` reports the actual payload
size without another copy and can be used for downstream policy. The reader
cannot choose either limit on behalf of the application.

## Installation

Require the package with Composer.

```bash
composer require swan-community/owid
```

The library needs PHP 8.1 or later with the openssl, mbstring, and json
extensions, all of which ship with a standard PHP build.

## Usage

Create a creator that holds the signing keys, create a signed OWID, serialize
it, then read it back later and verify it with the public key.

```php
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Owid;

// The creator operates a domain and holds the signing keys.
$crypto = Crypto::new();
$creator = new Creator('example.com', $crypto);

// Create a signed OWID with a payload. There is no unsigned stage.
$owid = $creator->create('Hello World');

// Serialize to base 64 for storage or transmission.
$encoded = $owid->asBase64();

// Later, or elsewhere, read it back. Input from outside may be anything at
// all, so reading answers rather than raising.
$result = Owid::tryFromBase64($encoded);
if ($result->ok) {
    $publicPem = $crypto->publicKeyPem();
    $valid = $result->owid->verifyWithPublicKey($publicPem);
} else {
    // $result->status names which of the expected problems it was, for
    // example ParseStatus::InvalidBase64 or ParseStatus::ByteCountMismatch.
    $reason = $result->status->value;
}
```

Chain OWIDs by creating one that covers others. The same others, in the same
order, must be supplied when verifying.

```php
$root = $creator->create('root');
$party = $creator->create('party', [$root]);

// Verifying the party requires the root as the single other.
$party->verifyWithPublicKey($crypto->publicKeyPem(), [$root]);
```

Where the difference between a signature that does not match and a check that
could not be made changes what your code should do, ask for the status instead
of a true or false answer. A key that cannot be read is reported as a fault in
the key and never as a forgery.

```php
use SwanCommunity\Owid\SignatureStatus;

$status = $owid->signatureStatus($crypto->publicKeyPem());
if ($status === SignatureStatus::SignatureValid) {
    // Genuine.
} elseif ($status === SignatureStatus::SignatureInvalid) {
    // The only status that means the identifier should be distrusted.
} else {
    // InvalidKey, VerificationError and the rest mean the question could not
    // be answered, which is an operational fault rather than an attack.
}
```

## How an OWID comes into existence

An OWID is only worth anything because it is signed, so a caller cannot build
one. An instance arrives by exactly two routes.

1. Reading bytes that were already a complete OWID, with `Owid::tryFromBase64`,
   `Owid::tryFromByteArray` or `Owid::tryFromFrame`.
2. `Creator::create`, which owns the version, the domain, the date and the
   signature, and returns a finished OWID.

The constructor is private and the fields are read only, both enforced by PHP
itself. There is no way to obtain a half made OWID and no way to sign one that
already exists, because an unsigned OWID is indistinguishable from a signed one
to the code downstream of it, and the difference only surfaces later when a
verification fails somewhere nobody is watching.

## Reading data that may not be an OWID

An OWID is read from whatever a caller was handed, which on a public end point
means anything at all, so being malformed is an ordinary outcome rather than an
exceptional one. The `try` methods report it instead of raising, because
raising costs the construction and unwinding of an exception for every bad
input and whoever sends the data chooses how often that happens.

Every read reports the same three facts.

1. `$result->ok`, whether it worked.
2. `$result->owid`, the OWID on success and null on failure.
3. `$result->status`, a `ParseStatus` naming the reason, which is `Parsed` on
   success.

A result also carries `$result->consumed`, the number of bytes the envelope
occupied, which a caller reading several OWIDs from one buffer adds to its
offset to reach the next.

`tryFromBase64` and `tryFromByteArray` require the value to be one whole OWID
and nothing else, so bytes after the envelope are refused. `tryFromFrame` reads
one OWID from a buffer that may carry more after it and leaves the rest alone,
because what follows may be the next envelope.

Reading is not verification. A successfully read OWID is structurally valid and
nothing more, and whether its signature is genuine is a separate question with
a separate answer.

## Interface

The public classes live in the `SwanCommunity\Owid` namespace.

- `Owid` is the node in a tree. It holds the version, domain, date, payload,
  and signature, all read only.
  - `Owid::tryFromBase64`, `Owid::tryFromByteArray` read one complete OWID and
    report a `ParseResult`.
  - `Owid::tryFromFrame` reads one OWID from a buffer that carries more after
    it, reporting how many bytes it occupied.
  - `asBase64`, `asByteArray` serialize an OWID.
  - `payloadAsString` returns the raw payload bytes, `payloadAsPrintable`
    returns lower case zero padded hexadecimal, `payloadAsBase64` returns the
    padded base 64 form.
  - `verifyWithCrypto`, `verifyWithPublicKey` answer true or false for the OWID
    and any others it was signed with.
  - `signatureStatus`, `signatureStatusWithCrypto` answer with a
    `SignatureStatus`, which keeps a signature that does not match apart from a
    check that could not be made.
  - `ageMinutes` returns the minutes elapsed since creation.
- `ParseResult` carries `ok`, `owid`, `status` and `consumed`.
- `ParseStatus` names why a read succeeded or failed, in the vocabulary shared
  with the other OWID implementations.
- `SignatureStatus` names the outcome of asking whether a signature is genuine.
- `Crypto` holds the keys.
  - `Crypto::new` generates a P-256 key pair.
  - `Crypto::newSignOnly` accepts a PKCS#8 or SEC1 private key PEM.
  - `Crypto::newVerifyOnly` accepts an SPKI public key PEM, and
    `Crypto::tryVerifyOnly` returns null instead of raising when the material
    cannot be read.
  - `signByteArray`, `verifyByteArray` and `verifySignatureStatus` operate on
    raw bytes.
  - `publicKeyPem`, `privateKeyPem` export the keys as PEM.
- `Creator` binds a domain to a signing `Crypto`.
  - `create($payload, $others = [])` creates and signs a new OWID in one call.
    A PHP string is a byte array, so the payload may be text or raw bytes.
- `Endpoints` returns the path and body strings for the well known end points
  without binding to any web framework.
- `Version` is the wire format version enum.
- `OwidException` is raised for a fault in the program, such as a creator
  configured with a domain that is too long, a key that cannot be used, or
  fields that cannot be written. Data arriving from outside is reported with a
  `ParseStatus` instead.

## Data structure notes

A signed OWID serializes to bytes in this order. Multi byte integers are
little endian unless stated otherwise.

| Field          | Bytes               | Description                                                  |
|----------------|---------------------|--------------------------------------------------------------|
| Version        | 1                   | The byte version of the OWID. Always the first byte.         |
| Domain         | length + 1          | Domain associated with the creator, null (0) terminated.     |
| Date           | 4 (2 for version 1) | Minutes elapsed since 2020-01-01 UTC as an unsigned integer. |
| Payload length | 4                   | Number of bytes that form the payload.                       |
| Payload        | variable            | Bytes that form the payload, if any.                         |
| Signature      | 64                  | ECDSA P-256 signature as the r and s values concatenated.    |

Version 1 stored the date as a two byte big endian count of hours since the
base date. Versions 1 and 2 are deprecated and supported for reading only.

The signature is stored as 64 raw bytes, the 32 byte big endian r value
followed by the 32 byte big endian s value. The openssl extension produces and
consumes ASN.1 DER signatures, so this library converts between the DER form
and the raw form when signing and verifying.

The data covered by the signature is this OWID without its signature, followed
by the complete bytes, including the signature, of each other OWID in the
order given. To verify, the same others must be supplied in the same order as
when signing.

Although the in memory date may carry more precision, the serialized form is
minutes since the base date, so signing and verification both operate on the
minute truncated value.

## Testing

The test suite exercises the canonical wire vectors, the cross language signed
fixtures with their chain and tamper assertions, the signing path, and unit
tests for the crypto, creator, io, and end point helpers.

Run the suite with PHPUnit after installing the development dependencies.

```bash
composer install
php vendor/bin/phpunit
```

A plain runner with no external dependency is also provided as a fallback when
PHPUnit is not available.

```bash
php tests/run.php
```

## License

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE)
file for the full text.
