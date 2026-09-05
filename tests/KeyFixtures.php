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

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use SwanCommunity\Owid\DatedPublicKey;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\ParseStatus;
use SwanCommunity\Owid\PublicKeySchedule;

/**
 * A genuine identifier and the published signing key schedule of the creator
 * that issued it, shared with the other OWID ports so that every port is
 * checked against the same real data.
 *
 * The identifier is a 51Did creator context identifier the 51Degrees cloud
 * issued on 4 September 2026 for the creator domain 51d.es. The schedule is
 * the thirty weekly keys the public key end point served for that domain from
 * 11 May to 30 November 2026. Both are public and carry no secret.
 */
final class KeyFixtures
{
    /**
     * The date the identifier carries, in whole minutes since 2020-01-01,
     * which is 2026-09-04T00:00:00Z because the cloud dates an identifier to
     * the day, and is the value a fetch names.
     */
    public const IDENTIFIER_MINUTES = 3510720;

    /** The creator domain the identifier carries. */
    public const IDENTIFIER_DOMAIN = '51d.es';

    private function __construct()
    {
    }

    /**
     * The start of the key that signed the identifier, being the week that
     * was running on 4 September 2026.
     */
    public static function weekOfTheIdentifier(): DateTimeImmutable
    {
        return self::instant('2026-08-31T00:00:00Z');
    }

    /** The genuine identifier, read from the fixture. */
    public static function identifier(): Owid
    {
        $records = self::records('identifier.txt');
        if (count($records) !== 1) {
            throw new RuntimeException('the fixture holds one identifier');
        }
        $result = Owid::tryFromBase64($records[0]);
        if ($result->status !== ParseStatus::Parsed || $result->owid === null) {
            throw new RuntimeException(
                'the genuine identifier should read: ' . $result->status->value
            );
        }
        return $result->owid;
    }

    /**
     * Every record of the published schedule, in the order published, being
     * the moment the key came into force, the moment the key material was
     * generated, and the PEM.
     *
     * @return array<int, array{startsAt: DateTimeImmutable, created: DateTimeImmutable, pem: string}>
     */
    public static function scheduledKeys(): array
    {
        $keys = [];
        foreach (self::records('public-key-schedule.txt') as $record) {
            $fields = explode(' ', $record);
            if (count($fields) !== 3) {
                throw new RuntimeException(
                    'a record is a start, a generation moment and a key'
                );
            }
            $keys[] = [
                'startsAt' => self::instant($fields[0]),
                'created' => self::instant($fields[1]),
                'pem' => self::pem($fields[2]),
            ];
        }
        return $keys;
    }

    /**
     * The published schedule as the library holds it, with only the start of
     * each key, because the generation moment plays no part in the choice.
     */
    public static function schedule(): PublicKeySchedule
    {
        $keys = [];
        foreach (self::scheduledKeys() as $key) {
            $keys[] = DatedPublicKey::of($key['startsAt'], $key['pem']);
        }
        return PublicKeySchedule::of($keys);
    }

    /**
     * Wraps the base 64 body of a Subject Public Key Info into the PEM form
     * the public key end point serves.
     */
    public static function pem(string $body): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split($body, 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Reads a moment written the way the schedule writes them, for example
     * 2026-08-31T00:00:00Z.
     */
    private static function instant(string $value): DateTimeImmutable
    {
        $moment = DateTimeImmutable::createFromFormat(
            'Y-m-d\TH:i:s\Z',
            $value,
            new DateTimeZone('UTC')
        );
        if ($moment === false) {
            throw new RuntimeException('not a moment: ' . $value);
        }
        return $moment;
    }

    /**
     * Reads a fixture, dropping the comment lines and the blank ones.
     *
     * @return array<int, string>
     */
    private static function records(string $name): array
    {
        $text = file_get_contents(__DIR__ . '/data/' . $name);
        if ($text === false) {
            throw new RuntimeException('should find the fixture ' . $name);
        }
        $records = [];
        foreach (preg_split('/\r?\n/', $text) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $records[] = $line;
        }
        return $records;
    }
}
