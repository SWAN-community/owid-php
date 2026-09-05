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
use PHPUnit\Framework\TestCase;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\DatedPublicKey;
use SwanCommunity\Owid\Endpoints;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\PublicKeySchedule;

/**
 * The public key end point of a creator that rotates its key, answering the
 * date parameter the way the specification requires: the key in force at the
 * date asked, the key in force now where no date is given or the date is
 * later than now, 404 where no key is in force, and 400 where the date is not
 * a count of minutes.
 */
final class PublicKeyResponseAtTest extends TestCase
{
    private DatedPublicKey $lastWeek;
    private DatedPublicKey $thisWeek;
    private DatedPublicKey $nextWeek;
    private PublicKeySchedule $schedule;
    private DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->lastWeek = DatedPublicKey::of(self::utc('2026-08-24T00:00:00Z'), self::freshPem());
        $this->thisWeek = DatedPublicKey::of(self::utc('2026-08-31T00:00:00Z'), self::freshPem());
        $this->nextWeek = DatedPublicKey::of(self::utc('2026-09-07T00:00:00Z'), self::freshPem());
        $this->schedule = PublicKeySchedule::of([$this->nextWeek, $this->lastWeek, $this->thisWeek]);
        // The moment of the request, in the week of 31 August 2026 with the
        // following week's key already published.
        $this->now = self::utc('2026-09-04T20:32:00Z');
    }

    private static function utc(string $value): DateTimeImmutable
    {
        return new DateTimeImmutable($value, new DateTimeZone('UTC'));
    }

    private static function freshPem(): string
    {
        return Crypto::new()->publicKeyPem();
    }

    private static function minutes(DateTimeImmutable $moment): string
    {
        return (string) Io::minutesSinceBase($moment);
    }

    public function testADatedRequestIsServedTheKeyInForceThen(): void
    {
        $this->assertSame(
            [200, $this->lastWeek->publicKeyPem],
            Endpoints::publicKeyResponseAt(
                $this->schedule,
                'pkcs',
                self::minutes(self::utc('2026-08-26T00:00:00Z')),
                $this->now
            )
        );
        $this->assertSame(
            [200, $this->thisWeek->publicKeyPem],
            Endpoints::publicKeyResponseAt($this->schedule, 'spki', self::minutes($this->now), $this->now)
        );
    }

    /**
     * The key in force now is not the last key of the schedule, which is one
     * whose period has not begun.
     */
    public function testAnUndatedRequestIsServedTheKeyInForceNow(): void
    {
        foreach ([null, ''] as $absent) {
            $this->assertSame(
                [200, $this->thisWeek->publicKeyPem],
                Endpoints::publicKeyResponseAt($this->schedule, 'pkcs', $absent, $this->now)
            );
        }
    }

    /**
     * A caller cannot ask for a key whose period has not begun, because a key
     * that has signed nothing yet has nothing to verify.
     */
    public function testAFutureDateIsReadAsNow(): void
    {
        $this->assertSame(
            [200, $this->thisWeek->publicKeyPem],
            Endpoints::publicKeyResponseAt(
                $this->schedule,
                'pkcs',
                self::minutes(self::utc('2026-09-08T00:00:00Z')),
                $this->now
            )
        );
    }

    /**
     * The largest value the field can hold is past the year 9999, and it is
     * after every key, so the answer is the key in force now rather than a
     * failure in the date arithmetic.
     */
    public function testADateBeyondTheCalendarIsReadAsNow(): void
    {
        $this->assertSame(
            [200, $this->thisWeek->publicKeyPem],
            Endpoints::publicKeyResponseAt($this->schedule, 'pkcs', (string) 0xFFFFFFFF, $this->now)
        );
    }

    public function testADateBeforeTheScheduleIs404(): void
    {
        $this->assertSame(
            [404, ''],
            Endpoints::publicKeyResponseAt(
                $this->schedule,
                'pkcs',
                self::minutes(self::utc('2026-08-23T00:00:00Z')),
                $this->now
            )
        );
        $this->assertSame(
            [404, ''],
            Endpoints::publicKeyResponseAt(PublicKeySchedule::of([]), 'pkcs', null, $this->now)
        );
    }

    public function testADateThatIsNotACountOfMinutesIs400(): void
    {
        foreach (['abc', '-1', '1.5', ' 12', '+5', '4294967296', '12345678901'] as $malformed) {
            $this->assertSame(
                [400, ''],
                Endpoints::publicKeyResponseAt($this->schedule, 'pkcs', $malformed, $this->now),
                'date ' . var_export($malformed, true)
            );
        }
    }

    public function testTheFormatMustBeSpkiOrPkcs(): void
    {
        $this->expectException(OwidException::class);
        Endpoints::publicKeyResponseAt($this->schedule, 'der', null, $this->now);
    }

    /**
     * Without a moment supplied the clock is used, so the answer is the
     * latest key that has started by the time the test runs.
     */
    public function testTheMomentOfTheRequestDefaultsToNow(): void
    {
        [$status, $body] = Endpoints::publicKeyResponseAt($this->schedule, 'pkcs', null);
        $this->assertSame(200, $status);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $body);
        $started = array_values(array_filter(
            $this->schedule->keys(),
            static fn (DatedPublicKey $key): bool =>
                $key->startsAt <= new DateTimeImmutable('now', new DateTimeZone('UTC'))
        ));
        $this->assertSame($started[count($started) - 1]->publicKeyPem, $body);
    }
}
