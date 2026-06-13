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

/**
 * Helpers for hosting the well known end points required by the OWID
 * specification. These are framework agnostic. They return the path and body
 * so that any HTTP server can serve them.
 *
 * The mandatory end points are the creator end point at
 * /owid/api/v{version}/creator returning JSON with the domain, common name,
 * and public key of the creator, and the public key end point at
 * /owid/api/v{version}/public-key returning the public key as PEM text where
 * the format query parameter must be spki or pkcs.
 */
final class Endpoints
{
    /**
     * Returns the path of the creator end point for the version provided. For
     * example /owid/api/v3/creator.
     */
    public static function creatorPath(Version $version): string
    {
        return '/owid/api/v' . $version->asByte() . '/creator';
    }

    /**
     * Returns the path of the public key end point for the version provided.
     * For example /owid/api/v3/public-key.
     */
    public static function publicKeyPath(Version $version): string
    {
        return '/owid/api/v' . $version->asByte() . '/public-key';
    }

    /**
     * Returns the JSON body for the creator end point. The fields match the
     * names required by the specification.
     *
     * @throws OwidException when the public key can not be exported or the
     *                       JSON can not be produced.
     */
    public static function creatorResponse(
        Creator $creator,
        string $name,
        string $contractUrl = ''
    ): string {
        $body = [
            'domain' => $creator->domain(),
            'name' => $name,
            'publicKeySPKI' => $creator->crypto()->subjectPublicKeyInfo(),
            'contractURL' => $contractUrl,
        ];
        $json = json_encode($body, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw OwidException::key(json_last_error_msg());
        }
        return $json;
    }

    /**
     * Returns the text body for the public key end point. The specification
     * allows the key to be requested in SPKI or PKCS form. This implementation
     * returns the SPKI PEM for both values because the importers in every
     * implementation accept it.
     *
     * @throws OwidException when the format is not spki or pkcs, or the public
     *                       key can not be exported.
     */
    public static function publicKeyResponse(Creator $creator, string $format): string
    {
        if ($format === 'spki' || $format === 'pkcs') {
            return $creator->crypto()->subjectPublicKeyInfo();
        }
        throw OwidException::invalidKeyFormat($format);
    }
}
