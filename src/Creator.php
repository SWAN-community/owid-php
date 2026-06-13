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
 * Needed to create new OWIDs.
 *
 * A creator binds the domain that hosts the well known end points to the
 * crypto instance holding the signing key.
 */
final class Creator
{
    private string $domain;
    private Crypto $crypto;

    /**
     * Creates a new creator for the domain using the crypto instance for
     * signing.
     *
     * @throws OwidException when the domain is empty or whitespace, or the
     *                       crypto instance can not sign.
     */
    public function __construct(string $domain, Crypto $crypto)
    {
        if (trim($domain) === '') {
            throw OwidException::invalidDomain($domain);
        }
        if (!$crypto->canSign()) {
            throw OwidException::keyMissing('generate a signature');
        }
        $this->domain = $domain;
        $this->crypto = $crypto;
    }

    /**
     * Creates a new creator from the domain and the private key PEM provided.
     *
     * @throws OwidException when the domain is empty or whitespace, or the
     *                       private key PEM is not valid.
     */
    public static function fromConfiguration(string $domain, string $privatePem): self
    {
        $crypto = Crypto::newSignOnly($privatePem);
        return new self($domain, $crypto);
    }

    /**
     * Domain associated with the OWID creator. Contains well known end points
     * to provide public keys and other information needed to conform to the
     * OWID specification.
     */
    public function domain(): string
    {
        return $this->domain;
    }

    /**
     * Used to sign OWIDs from this creator.
     */
    public function crypto(): Crypto
    {
        return $this->crypto;
    }

    /**
     * Signs the OWID provided, setting the domain to the creator domain, the
     * date to the current time, and the version to the current version.
     *
     * @throws OwidException when the fields can not be encoded or the signing
     *                       operation fails.
     */
    public function sign(Owid $owid): void
    {
        $this->signWithOthers($owid, []);
    }

    /**
     * Signs the OWID provided together with the other OWIDs provided. The same
     * others, in the same order, must be passed when verifying.
     *
     * @param array<int, Owid> $others
     *
     * @throws OwidException when the fields can not be encoded or the signing
     *                       operation fails.
     */
    public function signWithOthers(Owid $owid, array $others): void
    {
        $owid->version = Version::default();
        $owid->domain = $this->domain;
        $owid->date = new DateTimeImmutable('now');
        $data = $owid->dataForCrypto($others);
        $owid->signature = $this->crypto->signByteArray($data);
        if (strlen($owid->signature) !== OwidException::SIGNATURE_LENGTH) {
            throw OwidException::invalidSignatureLength(strlen($owid->signature));
        }
    }

    /**
     * Creates a new signed OWID for the creator containing the string as the
     * payload.
     *
     * @throws OwidException when the OWID can not be signed.
     */
    public function signString(string $value): Owid
    {
        return $this->signBytes($value);
    }

    /**
     * Creates a new signed OWID for the creator containing the bytes as the
     * payload.
     *
     * @throws OwidException when the OWID can not be signed.
     */
    public function signBytes(string $value): Owid
    {
        $owid = new Owid();
        $owid->payload = $value;
        $this->sign($owid);
        return $owid;
    }
}
