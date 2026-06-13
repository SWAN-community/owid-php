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
`verifyWithPublicKey` method accepts a public key PEM that the caller has
already obtained, so any HTTP client can supply it.

## Installation

Require the package with Composer.

```bash
composer require swan-community/owid
```

The library needs PHP 8.1 or later with the openssl, mbstring, and json
extensions, all of which ship with a standard PHP build.

## Usage

Create a creator that holds the signing keys, sign a payload, serialize it,
then decode and verify it later with the public key.

```php
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Owid;

// The creator operates a domain and holds the signing keys.
$crypto = Crypto::new();
$creator = new Creator('example.com', $crypto);

// Create and sign an OWID with a payload.
$owid = $creator->signString('Hello World');

// Serialize to base 64 for storage or transmission.
$encoded = $owid->asBase64();

// Later, or elsewhere, decode and verify with the creator public key.
$copy = Owid::fromBase64($encoded);
$publicPem = $crypto->publicKeyPem();
$valid = $copy->verifyWithPublicKey($publicPem);
```

Chain OWIDs by signing one together with others. The same others, in the same
order, must be supplied when verifying.

```php
$root = $creator->signString('root');

$party = new Owid();
$party->payload = 'party';
$creator->signWithOthers($party, [$root]);

// Verifying the party requires the root as the single other.
$party->verifyWithPublicKey($publicPem, [$root]);
```

## Interface

The public classes live in the `SwanCommunity\Owid` namespace.

- `Owid` is the node in a tree. It holds the version, domain, date, payload,
  and signature.
  - `Owid::fromBase64`, `Owid::fromByteArray` parse a signed OWID.
  - `asBase64`, `asByteArray` serialize a signed OWID.
  - `payloadAsString` returns the raw payload bytes, `payloadAsPrintable`
    returns lower case zero padded hexadecimal, `payloadAsBase64` returns the
    padded base 64 form.
  - `verifyWithCrypto`, `verifyWithPublicKey` verify the OWID and any others
    it was signed with.
  - `ageMinutes` returns the minutes elapsed since creation.
- `Crypto` holds the keys.
  - `Crypto::new` generates a P-256 key pair.
  - `Crypto::newSignOnly` accepts a PKCS#8 or SEC1 private key PEM.
  - `Crypto::newVerifyOnly` accepts an SPKI public key PEM.
  - `signByteArray`, `verifyByteArray` operate on raw bytes.
  - `publicKeyPem`, `privateKeyPem` export the keys as PEM.
- `Creator` binds a domain to a signing `Crypto`.
  - `sign`, `signWithOthers` set the domain, date, and version then sign.
  - `signString`, `signBytes` create and sign in one call.
- `Endpoints` returns the path and body strings for the well known end points
  without binding to any web framework.
- `Version` is the wire format version enum.
- `OwidException` is raised for every error.

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
