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

/**
 * Shared test vectors. The canonical wire vectors prove the reader and writer
 * match the wire format. The cross language fixtures hold real signatures
 * produced by other implementations and prove the verification path
 * interoperates.
 */
final class Fixtures
{
    /**
     * The CREATOR canonical wire vector. Version 2, domain 51db.uk, payload
     * length 341, date 664619 minutes after the base date. Unpadded base 64.
     */
    public const CANONICAL_CREATOR =
        'AjUxZGIudWsAKyQKAFUBAAABAWhlYWRpbmcAcG9wLXVwLnN3YW4tZGVtby51awAQAAAA27' .
        'eOAAPSTXmKZT79iWgRagI1MWRhLnVrACskCgAQAAAAs1WelonmS0KoK6uiN3rz1rAxJHj2' .
        'rNKvV/9OMOyFlWHY/tbwpdVupNG62p3pCWCuzgV2YMEth3coZhFSZHXJ1mO/U/bkHhGCSG' .
        '/BStI/fJcCNTFkYi51awArJAoAFAAAAO/c7j2xwwF8GN4hOXBIb/auLhy7mftegVZqvbep' .
        'qw8nVf8ByI94w9I/XLNwf5kAFpFeSeo8kwRhXqUyUuWT7FYIi4DnOP9zyTaAY8xgMh77oU' .
        'jL/QJjbXAuc3dhbi1kZW1vLnVrACskCgACAAAAb25Lyrbl9PDGs6VAMqgozsfxCqsVWX6p' .
        'f2JyFim3zg6lLivRDqpCD921elvxdn85/vK0msyTOMjE8buKAza/H2zBAEqEMbMuIoZL8J' .
        'i4m4ScYkpQvD3KjsLbqI5c7+Ra/Ju43vBMp2st7QLHD4sxwPugeSBEgQRkevAm0H1a3jek' .
        'MEA';

    /**
     * The SUPPLIER canonical wire vector. Version 2, domain pop-up.swan-demo.uk,
     * payload bytes 0x01 0x03. Unpadded base 64.
     */
    public const CANONICAL_SUPPLIER =
        'AnBvcC11cC5zd2FuLWRlbW8udWsAKyQKAAIAAAABA6Ljm9cxZfnmwRMjv4MQ0PrAjf8y29' .
        'Ru0sjZG5R+mkjBtQD9J02xZQIk5czsKJzOl6IkOPvbPSGakxyq0HPLX+w';

    /**
     * The BAD canonical wire vector. Parses but its signature does not verify.
     * Domain badssp.swan-demo.uk. Unpadded base 64.
     */
    public const CANONICAL_BAD =
        'AmJhZHNzcC5zd2FuLWRlbW8udWsAKyQKAAIAAAABAxu+OOtismihze3LlcNuvT2WXNTGSi' .
        'ogw36t85HLwL6YdV4i9kYDCdsP54RS8on/roKKASyh19TpcUQxkIRALFk';

    /**
     * The expected UTF-8 payload text for the utf8 cross language fixtures.
     */
    public const UTF8_PAYLOAD = "Z\u{00FC}rich \u{2764} OWID \u{00A3}\u{20AC}";

    /**
     * Returns the cross language fixtures keyed by implementation name. Each
     * entry has the SPKI public key PEM and the simple, utf8, chain_party and
     * chain_root base 64 OWIDs.
     *
     * @return array<string, array<string, string>>
     */
    public static function crossLanguage(): array
    {
        return [
            'go' => [
                'domain' => 'go.swan-demo.uk',
                'spki' =>
                    "-----BEGIN PUBLIC KEY-----\n" .
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeO51FrQ8AmCFjLnePUH1qQ4GWGxj\n" .
                    "1aL5ux6vNJFSRnGTVc5YC8kEwqfOaMEjVWqt4Gbq4+lEnIAgTl76YAGpcA==\n" .
                    "-----END PUBLIC KEY-----\n",
                'simple' =>
                    'A2dvLnN3YW4tZGVtby51awA/vTMABwAAAGV4YW1wbGVPIQZ/uhIjVxrROjMD' .
                    'fcAkRk8U4fYacm0Ck4aOxoRDJPK/QrKavqZqCf7cCKbNuJ0aA7GhVeuy4oj' .
                    'eSzNX56Qn',
                'utf8' =>
                    'A2dvLnN3YW4tZGVtby51awA/vTMAFgAAAFrDvHJpY2gg4p2kIE9XSUQgwqPi' .
                    'gqzxY+4QgUGt84xC9HxHmHXDt+wcB0Y9a6E+Txm2F147Qacbp0CtrF8x7QC' .
                    'WZfkcKCKNGSM8hYZEfYjJtViG+tA+',
                'chain_party' =>
                    'A2dvLnN3YW4tZGVtby51awA/vTMABQAAAHBhcnR5l7NyNmFw2lxqc4DKJWoq' .
                    '0UVd5ujGV/+fvVxqYTRlwCFxaSuwvnhLQQHjX5spxWb4O08IeuiuGCat1WF' .
                    'B/Wqlyw==',
                'chain_root' =>
                    'A2dvLnN3YW4tZGVtby51awA/vTMABAAAAHJvb3R/bEqzG8gAy9yTF1UMEtOl' .
                    'YXBBmn3a20jxXq5NmxIC8iuZvduOXKMf+K8VoAapkWwfpoDKQHS09Ihljas' .
                    'ZqC0k',
            ],
            'dotnet' => [
                'domain' => 'dotnet.swan-demo.uk',
                'spki' =>
                    "-----BEGIN PUBLIC KEY-----\n" .
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEec6dTi0JOYGP78lw7/zAjp3r73fZ\n" .
                    "A7zSi4Ov90sVxgmqZ4cI1sbj7AbsnBhqJDe5Hu14gDBjZWErL7KpkjEl0A==\n" .
                    "-----END PUBLIC KEY-----\n",
                'simple' =>
                    'A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAcAAABleGFtcGxlVegwXS00P/DU' .
                    '2FJbLjof8qc/BwrffhbKJkV42pqFd7nUD+KR/DxxRSfLlm77/kAyR/dLOcw' .
                    'EetjN1z9UWzyh0w==',
                'utf8' =>
                    'A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zABYAAABaw7xyaWNoIOKdpCBPV0lE' .
                    'IMKj4oKsVuaeaDUej0sF+cHfYj/icDBmlBLOviC6ZE28am8EtY+IGuesFcg' .
                    '2rKMybcsAxMmnrDtF2xsk1cJvHgoIYpSJJQ==',
                'chain_party' =>
                    'A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAUAAABwYXJ0eXtD6H4R7GbvRyFU' .
                    '+bCKgjMAZFFm8KHln80XPwQOBb/Ub9EZfE4Ml3ueRkKX51+MD98RFgTSmjb' .
                    'qrAnzFkLlilA=',
                'chain_root' =>
                    'A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAQAAAByb290fErj2LccPYCduWUW' .
                    '8vY2aBjrecDfnTpVpv3+SESJMFW5pcuPKEQik2rC0fWEoB5Vr6e0k5inrhU' .
                    'GiF2c2Y2YDw==',
            ],
            'rust' => [
                'domain' => 'rust.swan-demo.uk',
                'spki' =>
                    "-----BEGIN PUBLIC KEY-----\n" .
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQcDroVnBAGAvy1SyUz4MyFxP16ki\n" .
                    "aPLulPz92rmbDbFKB6p0xl3iatZQ0uADa+F9cZeemLKtlfPaaue/KvNQOw==\n" .
                    "-----END PUBLIC KEY-----\n",
                'simple' =>
                    'A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAHAAAAZXhhbXBsZQtzvD+xirWingyf' .
                    'DxbykxurSxK4XdixdGR5lR0xnHmv2IFSsVCub2Jd1jRg/vQJ8XnXuNljRp/' .
                    'ErjSOMMQo5CI=',
                'utf8' =>
                    'A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAWAAAAWsO8cmljaCDinaQgT1dJRCDC' .
                    'o+KCrDHenDds+W587AzXpBb94gmLOloeBJTlHnjCkez4Dz2yAPtjcoQ6M/ZU' .
                    'WDIobtJHE5n9a81pTsn/Kvi74Azzx4s=',
                'chain_party' =>
                    'A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAFAAAAcGFydHmJ7qaxWgIZUHmGOQb2' .
                    'xC+RuZNwrkMmo1SA9/MfI4SoEpRYdnteXAKUQXxTOK3lmQ3Qz3UwBB6gBb3' .
                    'Q8hi1Wx0R',
                'chain_root' =>
                    'A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAEAAAAcm9vdFd0+QLaBLGPyBrQO+VN' .
                    'unBIQZzw8/lhEiDOKTx36Dc93A0n0fzPDMt/C+BdWMqhnL4nVvyurb3IHR7' .
                    'DUAmgmO0=',
            ],
        ];
    }
}
