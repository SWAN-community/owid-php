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
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\PublicKeySchedule;
use SwanCommunity\Owid\SignatureStatus;

/**
 * Choosing the key that signed an identifier out of the schedule a creator
 * has published, checked against a genuine identifier the 51Degrees cloud
 * issued on 4 September 2026 and the thirty keys the cloud published for that
 * creator.
 *
 * The fault this guards against was found on 4 September 2026 in the .NET
 * port, which selected the key by the moment the key material was generated.
 * The cloud had generated thirteen weeks of keys in one run on 1 September,
 * so the newest generated key was one whose period had not begun, and a
 * genuine identifier was reported as not matching.
 */
final class PublicKeyScheduleTest extends TestCase
{
    private static function freshPem(): string
    {
        return Crypto::new()->publicKeyPem();
    }

    private static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }

    /**
     * The published key for the week of 31 August 2026 verifies the
     * identifier created on 4 September, checked directly against the record
     * rather than through the schedule, so the fixture itself is shown to be
     * sound.
     */
    public function testGenuineIdentifierVerifiesAgainstTheKeyInForceOnItsDate(): void
    {
        $owid = KeyFixtures::identifier();
        $week = array_values(array_filter(
            KeyFixtures::scheduledKeys(),
            static fn (array $key): bool => $key['startsAt'] == KeyFixtures::weekOfTheIdentifier()
        ));
        $this->assertCount(1, $week, 'the schedule holds that week once');
        $this->assertSame(
            SignatureStatus::SignatureValid,
            $owid->signatureStatus($week[0]['pem'])
        );
    }

    public function testScheduleVerifiesTheGenuineIdentifier(): void
    {
        $owid = KeyFixtures::identifier();
        $schedule = KeyFixtures::schedule();
        $chosen = $schedule->keyFor($owid);
        $this->assertNotNull($chosen);
        $this->assertEquals(KeyFixtures::weekOfTheIdentifier(), $chosen->startsAt);
        $this->assertSame(SignatureStatus::SignatureValid, $schedule->signatureStatus($owid));
        $this->assertTrue($schedule->verify($owid));
    }

    /**
     * The key that started after the identifier was signed reports the
     * signature as not matching, which is the answer a verifier that took the
     * newest key would have given for a genuine identifier.
     */
    public function testALaterWeeksKeyDoesNotVerifyAnEarlierWeeksIdentifier(): void
    {
        $owid = KeyFixtures::identifier();
        $schedule = KeyFixtures::schedule();
        $keys = $schedule->keys();
        $signing = $schedule->keyFor($owid);
        $this->assertNotNull($signing);
        $following = $keys[array_search($signing, $keys, true) + 1];
        $this->assertGreaterThan($owid->date, $following->startsAt);
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            $owid->signatureStatus($following->publicKeyPem)
        );
    }

    /**
     * A schedule is published ahead of time, so its last key is one whose
     * period has not begun, and serving that where the current key was meant
     * would fail every check of an identifier signed today.
     */
    public function testTheLastKeyIsNotTheKeyInForce(): void
    {
        $now = self::now();
        $schedule = PublicKeySchedule::of([
            DatedPublicKey::of($now->modify('-7 days'), self::freshPem()),
            DatedPublicKey::of($now->modify('+7 days'), self::freshPem()),
        ]);
        $this->assertEquals(
            $now->modify('+7 days'),
            $schedule->last()?->startsAt,
            'the last key is the one with the latest start'
        );
        $this->assertEquals(
            $now->modify('-7 days'),
            $schedule->current()?->startsAt,
            'the key in force now is the one that has started'
        );
    }

    /**
     * The shape that broke the .NET port. Thirteen of the published keys were
     * generated in one batch on 1 September 2026 and cover the weeks from 7
     * September to 30 November, so on 4 September the newest key that had
     * already been generated was one that had not started yet.
     */
    public function testSelectionIgnoresTheMomentTheKeysWereGenerated(): void
    {
        $owid = KeyFixtures::identifier();
        $published = KeyFixtures::scheduledKeys();
        $newestGenerated = null;
        foreach ($published as $key) {
            if ($key['created'] > $owid->date) {
                continue;
            }
            if ($newestGenerated === null || $key['created'] > $newestGenerated['created']) {
                $newestGenerated = $key;
            }
        }
        $this->assertNotNull($newestGenerated, 'keys were generated before the date');
        $sharingTheBatch = 0;
        foreach ($published as $key) {
            if ($key['created'] == $newestGenerated['created']) {
                $sharingTheBatch++;
            }
        }
        $this->assertSame(13, $sharingTheBatch, 'thirteen keys share the generation moment of 1 September');
        $this->assertGreaterThan(
            $owid->date,
            $newestGenerated['startsAt'],
            'the newest generated key had not started when the identifier was signed'
        );
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            $owid->signatureStatus($newestGenerated['pem']),
            'selecting on the generation moment reports a genuine identifier as not matching'
        );
        $chosen = KeyFixtures::schedule()->keyFor($owid);
        $this->assertNotNull($chosen, 'the schedule covers the date');
        $this->assertEquals(
            KeyFixtures::weekOfTheIdentifier(),
            $chosen->startsAt,
            'selecting on the start picks the week that was running'
        );
        $this->assertSame(
            SignatureStatus::SignatureValid,
            $owid->signatureStatus($chosen->publicKeyPem),
            'selecting on the start verifies the genuine identifier'
        );
    }

    public function testAKeyIsInForceFromItsStartUntilTheNextStart(): void
    {
        $schedule = KeyFixtures::schedule();
        $keys = $schedule->keys();
        for ($index = 1; $index < count($keys); $index++) {
            $previous = $keys[$index - 1];
            $key = $keys[$index];
            $start = $key->startsAt;
            $this->assertEquals(
                $key->startsAt,
                $schedule->keyInForce($start)?->startsAt,
                'the start belongs to the key that is starting'
            );
            $this->assertEquals(
                $previous->startsAt,
                $schedule->keyInForce($start->modify('-1 minute'))?->startsAt,
                'the minute before the start belongs to the key before'
            );
            $this->assertEquals(
                $key->startsAt,
                $schedule->keyInForce($start->modify('+6 days'))?->startsAt,
                'the rest of the week belongs to the key that started'
            );
        }
    }

    public function testKeysMayArriveInAnyOrder(): void
    {
        $forwards = KeyFixtures::schedule()->keys();
        $backwards = PublicKeySchedule::of(array_reverse($forwards))->keys();
        $this->assertEquals(
            array_map(static fn (DatedPublicKey $key): DateTimeImmutable => $key->startsAt, $forwards),
            array_map(static fn (DatedPublicKey $key): DateTimeImmutable => $key->startsAt, $backwards),
            'the schedule is held oldest start first whatever the order given'
        );
        $this->assertCount(count($forwards), PublicKeySchedule::of(array_reverse($forwards)));
    }

    public function testADateBeforeTheScheduleHasNoKey(): void
    {
        $schedule = KeyFixtures::schedule();
        $before = $schedule->keys()[0]->startsAt->modify('-1 minute');
        $this->assertNull($schedule->keyInForce($before));
        $this->assertNull($schedule->keyInForce(null));
        $owid = KeyFixtures::identifier();
        $lateStart = PublicKeySchedule::of([
            DatedPublicKey::of($owid->date->modify('+1 day'), self::freshPem()),
        ]);
        $this->assertNull($lateStart->keyFor($owid));
        $this->assertSame(SignatureStatus::KeyUnavailable, $lateStart->signatureStatus($owid));
        $this->assertFalse($lateStart->verify($owid));
    }

    public function testAnEmptyScheduleHasNoKey(): void
    {
        $schedule = PublicKeySchedule::of([]);
        $this->assertCount(0, $schedule);
        $this->assertNull($schedule->last());
        $this->assertNull($schedule->current());
        $this->assertNull($schedule->keyInForce(self::now()));
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            $schedule->signatureStatus(KeyFixtures::identifier())
        );
    }

    public function testAMissingOwidIsKeyUnavailable(): void
    {
        $schedule = KeyFixtures::schedule();
        $this->assertNull($schedule->keyFor(null));
        $this->assertSame(SignatureStatus::KeyUnavailable, $schedule->signatureStatus(null));
        $this->assertFalse($schedule->verify(null));
    }

    /**
     * A creator does not publish two keys for one start, so the case is
     * settled the way the cloud settles it rather than left to chance.
     */
    public function testTwoKeysSharingAStartAreSettledInFavourOfTheFirstSupplied(): void
    {
        $start = new DateTimeImmutable('2026-08-31T00:00:00Z', new DateTimeZone('UTC'));
        $first = DatedPublicKey::of($start, self::freshPem());
        $second = DatedPublicKey::of($start, self::freshPem());
        $schedule = PublicKeySchedule::of([$second, $first]);
        $this->assertSame($second, $schedule->keyInForce($start));
        $this->assertSame($second, $schedule->keyInForce($start->modify('+3 days')));
        $reordered = PublicKeySchedule::of([$first, $second]);
        $this->assertSame($first, $reordered->keyInForce($start));
    }

    /** A start given in another zone is held in UTC and compared as an instant. */
    public function testStartsAreHeldInUtc(): void
    {
        $inZone = new DateTimeImmutable('2026-08-31T02:00:00+02:00');
        $key = DatedPublicKey::of($inZone, self::freshPem());
        $this->assertSame('UTC', $key->startsAt->getTimezone()->getName());
        $this->assertSame('2026-08-31T00:00:00Z', $key->startsAt->format('Y-m-d\TH:i:s\Z'));
    }

    public function testMissingValuesAreRefused(): void
    {
        try {
            PublicKeySchedule::of([null]);
            $this->fail('a missing key is refused');
        } catch (OwidException $refused) {
            $this->assertStringContainsString('missing', $refused->getMessage());
        }
        try {
            PublicKeySchedule::of(['not a key']);
            $this->fail('a value that is not a key is refused');
        } catch (OwidException $refused) {
            $this->assertStringContainsString('missing', $refused->getMessage());
        }
        foreach (['', '   '] as $empty) {
            try {
                DatedPublicKey::of(self::now(), $empty);
                $this->fail('an empty PEM is refused');
            } catch (OwidException $refused) {
                $this->assertStringContainsString('empty', $refused->getMessage());
            }
        }
    }

    public function testTheKeysHandedOutCannotBeChanged(): void
    {
        $schedule = KeyFixtures::schedule();
        $keys = $schedule->keys();
        $keys[0] = DatedPublicKey::of(self::now(), self::freshPem());
        $this->assertNotSame($keys[0], $schedule->keys()[0], 'the array handed out is a copy');
        $this->assertCount(30, $schedule, 'the published schedule holds thirty keys');
        $this->expectException(\Error::class);
        // @phpstan-ignore-next-line the assignment is the thing under test
        $schedule->keys()[0]->startsAt = self::now();
    }
}
