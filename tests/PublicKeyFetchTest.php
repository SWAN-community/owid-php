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
use Exception;
use PHPUnit\Framework\TestCase;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\DatedPublicKey;
use SwanCommunity\Owid\Endpoints;
use SwanCommunity\Owid\PublicKeySchedule;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\PublicKeyFetch;
use SwanCommunity\Owid\PublicKeyFetchException;
use SwanCommunity\Owid\SignatureStatus;
use SwanCommunity\Owid\Version;

/**
 * Fetching the key that was in force when an identifier was signed, from the
 * well known end point on the creator domain.
 *
 * The live end point answers 401 without a credential, so these tests run
 * against a stand in on the loopback address which serves the real published
 * 51d.es schedule. The URL under test is the one the library builds, with
 * only the host replaced, so a fault in the path or the query is caught here.
 */
final class PublicKeyFetchTest extends TestCase
{
    /** @var array<int, KeyEndPoint> */
    private array $started = [];

    protected function setUp(): void
    {
        // Keys are held by the creator's key end point, and a test that
        // counts requests has to start from nothing held.
        PublicKeyFetch::clearCache();
    }

    protected function tearDown(): void
    {
        foreach ($this->started as $endPoint) {
            $endPoint->stop();
        }
        $this->started = [];
        PublicKeyFetch::clearCache();
    }

    /** Starts a stand in end point and stops it when the test ends. */
    private function endPoint(string $answer = KeyEndPoint::ANSWER_SCHEDULE): KeyEndPoint
    {
        $endPoint = KeyEndPoint::start($answer);
        $this->started[] = $endPoint;
        return $endPoint;
    }

    /** The date the fixture identifier carries, which the cloud trims to the day. */
    private static function identifierDate(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-09-04T00:00:00Z', new DateTimeZone('UTC'));
    }

    /**
     * Builds an OWID with the version, domain and date given and a signature
     * of zeroes, for the cases that are about the URL rather than the
     * signature. Reading it back is the only way an OWID reaches a caller,
     * so the bytes are written and then read.
     */
    private static function crafted(Version $version, string $domain, DateTimeImmutable $date): Owid
    {
        $buffer = '';
        Io::writeByte($buffer, $version->asByte());
        Io::writeString($buffer, $domain);
        Io::writeDate($buffer, $date, $version);
        Io::writeByteArray($buffer, '');
        Io::writeSignature($buffer, str_repeat("\0", OwidException::SIGNATURE_LENGTH));
        $result = Owid::tryFromByteArray($buffer);
        self::assertTrue($result->ok, $result->status->value);
        self::assertNotNull($result->owid);
        return $result->owid;
    }

    /**
     * The URL names the minute the identifier was created, which is the
     * value the end point selects a key by, and it names the well known path
     * from the specification.
     */
    public function testUrlNamesTheMinuteTheIdentifierWasCreated(): void
    {
        $this->assertSame(
            'https://51d.es/owid/api/v3/public-key?date='
                . KeyFixtures::IDENTIFIER_MINUTES . '&format=pkcs',
            PublicKeyFetch::publicKeyUrl(KeyFixtures::identifier(), 'https'),
            'should ask 51d.es for the key in force on 4 September 2026'
        );
    }

    /**
     * The version in the path comes from the version byte of the identifier
     * rather than from a constant, so an identifier written by an earlier
     * version asks the end point that serves that version.
     */
    public function testUrlUsesTheVersionTheIdentifierCarries(): void
    {
        $version2 = self::crafted(Version::Version2, 'example.com', self::identifierDate());
        $this->assertSame(Version::Version2, $version2->version);
        $this->assertSame(
            'https://example.com/owid/api/v2/public-key?date='
                . KeyFixtures::IDENTIFIER_MINUTES . '&format=pkcs',
            PublicKeyFetch::publicKeyUrl($version2, 'https'),
            'should ask the version 2 end point'
        );
    }

    public function testUrlOfANewlySignedOwidNamesItsOwnMinute(): void
    {
        $creator = new Creator('example.com', Crypto::new());
        $owid = $creator->create('payload');
        $this->assertSame(
            'https://example.com/owid/api/v3/public-key?date='
                . Io::minutesSinceBase($owid->date) . '&format=pkcs',
            PublicKeyFetch::publicKeyUrl($owid, 'https'),
            'should name the minute the OWID was signed'
        );
    }

    /**
     * The fetch asks for the key in force when the identifier was signed and
     * verifies it, with the identifier signed in a week earlier than the one
     * the end point counts as current.
     */
    public function testDatedFetchVerifiesAnIdentifierFromAnEarlierKeyWeek(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = $this->endPoint();
        $this->assertSame(
            SignatureStatus::SignatureValid,
            PublicKeyFetch::signatureStatusAtUrl($owid, $endPoint->urlFor($owid)),
            'should verify against the key in force when it was signed'
        );
        $this->assertSame(
            [(string) KeyFixtures::IDENTIFIER_MINUTES],
            $endPoint->dates(),
            'the request should name the minute the identifier was created'
        );
    }

    /**
     * The same identifier against the same end point without the date, which
     * is the request a port that forgets the date makes. The end point
     * answers with the key in force at the moment of the request, ten days
     * after the identifier was signed, and states a span that does not reach
     * back to the identifier's date. The signature does not match that key,
     * and because the creator itself says the key was not in force then, the
     * key is reported as unavailable rather than the identifier as a forgery.
     */
    public function testUndatedFetchLeavesAnEarlierWeeksIdentifierUnverified(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = $this->endPoint();
        $undated = $endPoint->base . '/owid/api/v3/public-key?format=pkcs';
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatusAtUrl($owid, $undated),
            'an undated request gets the key in force at the request, which the creator says did not sign it'
        );
        $this->assertSame([null], $endPoint->dates(), 'the request carried no date');
    }

    /**
     * An end point that cannot serve a key for the date leaves the signature
     * unjudged rather than reporting a genuine identifier as a forgery.
     */
    public function testAKeyTheEndPointCannotServeIsKeyUnavailable(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = $this->endPoint();
        // A fortnight before the schedule begins, which no key in it covers,
        // so the end point answers 404 the way the cloud does.
        $before = KeyFixtures::scheduledKeys()[0]['startsAt']->modify('-14 days');
        $url = $endPoint->base . '/owid/api/v3/public-key?date='
            . Io::minutesSinceBase($before) . '&format=pkcs';
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatusAtUrl($owid, $url),
            'no key means the signature was never examined'
        );
    }

    /** The refusal carries the code and the domain, not only a message. */
    public function testARefusedRequestCarriesTheStatusAndTheCode(): void
    {
        $endPoint = $this->endPoint();
        $url = $endPoint->base . '/owid/api/v3/public-key?date=0&format=pkcs';
        try {
            PublicKeyFetch::publicKeyPemAtUrl($url, '51d.es');
            $this->fail('a date the schedule does not reach is refused');
        } catch (PublicKeyFetchException $refused) {
            $this->assertSame(SignatureStatus::KeyUnavailable, $refused->status());
            $this->assertSame(404, $refused->statusCode());
            $this->assertSame('51d.es', $refused->domain());
        }
    }

    /**
     * The stand in refuses a date that is not a count of minutes with a 400,
     * as the cloud does, and the library reports the refusal as a key that
     * could not be obtained.
     */
    public function testAMalformedDateIsRefusedByTheEndPoint(): void
    {
        $endPoint = $this->endPoint();
        $url = $endPoint->base . '/owid/api/v3/public-key?date=abc&format=pkcs';
        try {
            PublicKeyFetch::publicKeyPemAtUrl($url, '51d.es');
            $this->fail('a malformed date is refused');
        } catch (PublicKeyFetchException $refused) {
            $this->assertSame(SignatureStatus::KeyUnavailable, $refused->status());
            $this->assertSame(400, $refused->statusCode());
        }
    }

    /**
     * An end point that cannot be reached at all leaves the signature
     * unjudged. Nothing about the identifier is known, so calling it invalid
     * would report an outage as an attack.
     */
    public function testAnEndPointThatCannotBeReachedIsKeyUnavailable(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = KeyEndPoint::start();
        $url = $endPoint->urlFor($owid);
        $endPoint->stop();
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatusAtUrl($owid, $url),
            'a connection that is refused leaves the signature unjudged'
        );
    }

    /**
     * Text shaped like a PEM that holds no key is a fault in the key, and
     * never a signature that does not match.
     */
    /**
     * A creator whose domain answers with a redirect does not get the key
     * at the other end trusted as its own. The answer is that the key is
     * unavailable, carrying the 302, and the request that would have gone
     * to the other host is never made. Without this a network attacker
     * who could bend a creator's DNS, or a misconfigured creator, could
     * substitute the key and forgeries would verify.
     */
    public function testARedirectIsNotFollowed(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_REDIRECT);
        try {
            PublicKeyFetch::publicKeyPemAtUrl($endPoint->urlFor($owid), $owid->domain);
            $this->fail('a redirect must not yield a key');
        } catch (PublicKeyFetchException $refused) {
            $this->assertSame(SignatureStatus::KeyUnavailable, $refused->status());
            $this->assertSame(302, $refused->statusCode());
        }
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatusAtUrl($owid, $endPoint->urlFor($owid))
        );
    }

    public function testAKeyThatCannotBeReadIsInvalidKey(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_BROKEN_KEY);
        $this->assertSame(
            SignatureStatus::InvalidKey,
            PublicKeyFetch::signatureStatusAtUrl($owid, $endPoint->urlFor($owid))
        );
    }

    /**
     * Keys are held by the creator's key end point, each against the span
     * the creator stated for it, so two identifiers from different weeks
     * fetch two different keys and a key held for one week never answers
     * for another.
     * A store keyed by domain alone would hand the second identifier the
     * first one's key.
     */
    public function testKeysAreHeldPerRequestAndNotPerDomain(): void
    {
        $endPoint = $this->endPoint();
        $earlier = self::crafted(
            Version::Version3,
            KeyFixtures::IDENTIFIER_DOMAIN,
            self::identifierDate()->modify('-14 days')
        );
        $later = self::crafted(
            Version::Version3,
            KeyFixtures::IDENTIFIER_DOMAIN,
            self::identifierDate()
        );
        $first = PublicKeyFetch::publicKeyPemAtUrl(
            $endPoint->urlFor($earlier),
            KeyFixtures::IDENTIFIER_DOMAIN
        );
        $second = PublicKeyFetch::publicKeyPemAtUrl(
            $endPoint->urlFor($later),
            KeyFixtures::IDENTIFIER_DOMAIN
        );
        $this->assertNotSame($first, $second, 'two weeks, two keys');
        $this->assertCount(2, $endPoint->dates(), 'one request per week');
        $again = PublicKeyFetch::publicKeyPemAtUrl(
            $endPoint->urlFor($earlier),
            KeyFixtures::IDENTIFIER_DOMAIN
        );
        $this->assertSame($first, $again, 'the held key is the one fetched for that week');
        $this->assertCount(2, $endPoint->dates(), 'a week already held is not asked for again');
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $first);
    }

    /**
     * When the store reaches its bound it is emptied and filled again, so a
     * long running verifier never holds more than the bound. Driven through
     * a transport of the test's own, so a thousand fetches cost nothing.
     */
    public function testTheCacheIsBounded(): void
    {
        $requests = 0;
        // Every minute is answered with a different key, which is the worst a
        // creator can do to the cache, so the bound is on keys rather than
        // on the minutes one key covers.
        $counting = function (string $url, float $timeout) use (&$requests): array {
            $requests++;
            $minute = substr($url, strpos($url, 'date=') + 5);
            $minute = substr($minute, 0, strpos($minute, '&'));
            return [200, Endpoints::publicKeyAnswer(self::distinctPem((int) $minute), null, null, null)];
        };
        $urlFor = static fn (int $minute): string =>
            'https://example.invalid/owid/api/v3/public-key?date=' . $minute . '&format=pkcs';
        for ($minute = 1; $minute <= PublicKeyFetch::MAXIMUM_CACHED_KEYS + 1; $minute++) {
            PublicKeyFetch::publicKeyPemAtUrl($urlFor($minute), 'example.invalid', $counting);
        }
        $this->assertSame(PublicKeyFetch::MAXIMUM_CACHED_KEYS + 1, $requests);
        $this->assertLessThanOrEqual(
            PublicKeyFetch::MAXIMUM_CACHED_KEYS,
            PublicKeyFetch::cachedKeyCount(),
            'held ' . PublicKeyFetch::cachedKeyCount() . ' of at most ' . PublicKeyFetch::MAXIMUM_CACHED_KEYS
        );
        // The arrival past the bound emptied the store, so the first URL is
        // fetched again rather than answered from what was held.
        PublicKeyFetch::publicKeyPemAtUrl($urlFor(1), 'example.invalid', $counting);
        $this->assertSame(PublicKeyFetch::MAXIMUM_CACHED_KEYS + 2, $requests);
        // The last arrival is held, so asking for it again costs nothing.
        PublicKeyFetch::publicKeyPemAtUrl(
            $urlFor(PublicKeyFetch::MAXIMUM_CACHED_KEYS + 1),
            'example.invalid',
            $counting
        );
        $this->assertSame(PublicKeyFetch::MAXIMUM_CACHED_KEYS + 2, $requests);
    }

    /** A moment given as RFC 3339 text. */
    private static function moment(string $text): DateTimeImmutable
    {
        return new DateTimeImmutable($text, new DateTimeZone('UTC'));
    }

    /** The PEM the fetch answers for an identifier from the fixture domain dated at the moment. */
    private static function pemAt(KeyEndPoint $endPoint, DateTimeImmutable $moment): string
    {
        return PublicKeyFetch::publicKeyPemAtUrl(
            $endPoint->urlFor(self::crafted(Version::Version3, KeyFixtures::IDENTIFIER_DOMAIN, $moment)),
            KeyFixtures::IDENTIFIER_DOMAIN
        );
    }

    /** The PEM the published schedule says was in force at the moment. */
    private static function inForce(DateTimeImmutable $moment): string
    {
        $key = KeyFixtures::schedule()->keyInForce($moment);
        self::assertNotNull($key);
        return $key->publicKeyPem;
    }

    /**
     * A key the creator has confirmed for two minutes is served for every
     * minute between them without a request, because a key is in force from
     * the start of its period until the next key starts. A minute outside
     * every confirmed span is asked about.
     */
    public function testAMinuteBetweenTwoConfirmedMinutesIsServedFromTheCache(): void
    {
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_SPANLESS);
        // The week of 31 August 2026, which the fixture identifier was signed
        // in, and which is wholly in the past so the cache reads each minute
        // as itself rather than as now.
        $first = self::moment('2026-08-31T00:01:00Z');
        $last = self::moment('2026-09-06T23:00:00Z');
        $pem = self::pemAt($endPoint, $first);
        $this->assertSame($pem, self::pemAt($endPoint, $last), 'one key covers the week');
        $this->assertCount(2, $endPoint->dates(), 'the two ends of the span were asked about');
        foreach ([$first->modify('+1 minute'), $first->modify('+3 days'), $last->modify('-1 minute')] as $between) {
            $this->assertSame($pem, self::pemAt($endPoint, $between));
        }
        $this->assertCount(2, $endPoint->dates(), 'a minute between two confirmed minutes is not asked about');
        $this->assertSame(1, PublicKeyFetch::cachedKeyCount(), 'one key is held however many minutes it covers');
        $this->assertNotSame(
            $pem,
            self::pemAt($endPoint, $first->modify('-2 minutes')),
            'a minute in the week before is the earlier week\'s key'
        );
        $this->assertCount(3, $endPoint->dates(), 'a minute before the span is asked about');
        $this->assertSame(2, PublicKeyFetch::cachedKeyCount(), 'the earlier week\'s key is held as a second key');
    }

    /**
     * The case that made the cache almost useless when it was keyed by the
     * whole URL. A hundred identifiers with a hundred different minutes
     * inside one key's period cost a hundred requests then. With the ends of
     * the period confirmed they cost none.
     */
    public function testAHundredIdentifiersInOneConfirmedPeriodMakeNoRequest(): void
    {
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_SPANLESS);
        $start = self::moment('2026-09-01T00:00:00Z');
        self::pemAt($endPoint, $start);
        self::pemAt($endPoint, $start->modify('+100 minutes'));
        for ($i = 1; $i <= 100; $i++) {
            self::pemAt($endPoint, $start->modify('+' . $i . ' minutes'));
        }
        $this->assertCount(
            2,
            $endPoint->dates(),
            'a hundred identifiers over a hundred minutes made no request once both ends of the span were known'
        );
    }

    /**
     * A key is only ever served for a minute inside the span the creator has
     * confirmed it for. Where the creator rotated between two confirmed
     * minutes, the minutes between them belong to neither key until the
     * creator is asked, and every answer agrees with the published schedule.
     */
    public function testAKeyIsNeverServedForAMinuteOutsideItsConfirmedSpan(): void
    {
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_SPANLESS);
        $rotation = self::moment('2026-08-31T00:00:00Z');
        // The start of the week before the rotation and the end of the week
        // after it, so the two keys are held with the rotation between.
        self::pemAt($endPoint, $rotation->modify('-7 days'));
        self::pemAt($endPoint, $rotation->modify('+7 days -1 minute'));
        $this->assertCount(2, $endPoint->dates());
        $this->assertSame(2, PublicKeyFetch::cachedKeyCount());

        // Every minute across the rotation, in an order that walks in from
        // both sides, is answered with the key the schedule gives, whether
        // from the cache or by asking.
        $offsets = ['-1 minute', '+0 minutes', '-2 minutes', '+1 minute', '-84 hours', '+84 hours',
            '-3 minutes', '+2 minutes', '-1 minute', '+0 minutes'];
        foreach ($offsets as $offset) {
            $moment = $rotation->modify($offset);
            $this->assertSame(
                self::inForce($moment),
                self::pemAt($endPoint, $moment),
                'the key served for ' . $moment->format(DATE_ATOM)
            );
        }
        $this->assertSame(2, PublicKeyFetch::cachedKeyCount(), 'two keys are held, each with its own span');
        $asked = count($endPoint->dates());
        $this->assertTrue(
            $asked > 2 && $asked < 2 + count($offsets),
            'some minutes were asked about and some were served: ' . $asked
        );

        // The minute either side of the rotation is now confirmed, so nothing
        // across the whole fortnight needs asking.
        for ($moment = $rotation->modify('-7 days'); $moment < $rotation->modify('+7 days'); $moment = $moment->modify('+1 hour')) {
            $this->assertSame(
                self::inForce($moment),
                self::pemAt($endPoint, $moment),
                'the key served for ' . $moment->format(DATE_ATOM)
            );
        }
        $this->assertCount($asked, $endPoint->dates(), 'both spans are fully confirmed, so nothing was asked');
    }

    /**
     * A minute within the clock drift allowance of now, or later, is asked
     * about every time and never held, because a creator whose clock differs
     * from this one's may have read it as its present rather than as the
     * minute named. A minute beyond the allowance is held as usual.
     */
    public function testAMinuteWithinTheDriftAllowanceIsNotHeld(): void
    {
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_SPANLESS);
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $started = Io::minutesSinceBase($now);
        $recent = $now->modify('-1 minute');
        self::pemAt($endPoint, $recent);
        self::pemAt($endPoint, $recent);
        self::pemAt($endPoint, $now->modify('+7 days'));
        PublicKeyFetch::publicKeyPemAtUrl(
            $endPoint->base . '/owid/api/v3/public-key?format=pkcs',
            KeyFixtures::IDENTIFIER_DOMAIN
        );
        $old = $now->modify('-' . (PublicKeyFetch::CLOCK_DRIFT_ALLOWANCE_MINUTES + 1) . ' minutes');
        self::pemAt($endPoint, $old);
        self::pemAt($endPoint, $old);
        if (Io::minutesSinceBase(new DateTimeImmutable('now', new DateTimeZone('UTC'))) !== $started) {
            $this->markTestSkipped('the minute changed during the test, so the calls were not all about the same now');
        }
        $this->assertCount(
            5,
            $endPoint->dates(),
            'the recent minute was asked about twice, the future minute and the request with no date once each, '
                . 'and the old minute once with the second call held'
        );
        $this->assertSame(1, PublicKeyFetch::cachedKeyCount(), 'only the old minute\'s key is held');
    }

    /** A real public key for every value, made once and kept. */
    private static array $distinctKeys = [];

    private static function distinctPem(int $value): string
    {
        if (!isset(self::$distinctKeys[$value])) {
            self::$distinctKeys[$value] = Crypto::new()->publicKeyPem();
        }
        return self::$distinctKeys[$value];
    }

    /**
     * An identifier for the domain dated at the moment and signed with the
     * crypto given, standing for one whose signing machine's clock did not
     * agree with the creator's schedule to the minute.
     */
    private static function signedAt(string $domain, DateTimeImmutable $moment, Crypto $crypto): Owid
    {
        $data = '';
        Io::writeByte($data, Version::Version3->asByte());
        Io::writeString($data, $domain);
        Io::writeDate($data, $moment, Version::Version3);
        Io::writeByteArray($data, 'payload');
        $buffer = $data;
        Io::writeSignature($buffer, $crypto->signByteArray($data));
        $result = Owid::tryFromByteArray($buffer);
        self::assertTrue($result->ok, $result->status->value);
        self::assertNotNull($result->owid);
        return $result->owid;
    }

    /**
     * A creator that states the moments the key is valid from and to, which
     * is what the library's own server side helper answers, has the whole
     * span held from that one answer, so every other minute of the span is
     * served without a request.
     */
    public function testAKeyAnsweredWithItsSpanIsHeldForTheWholeSpan(): void
    {
        $endPoint = $this->endPoint();
        $pem = self::pemAt($endPoint, self::moment('2026-08-31T00:01:00Z'));
        foreach (['2026-09-06T23:59:00Z', '2026-09-03T12:00:00Z', '2026-08-31T00:00:00Z'] as $moment) {
            $this->assertSame($pem, self::pemAt($endPoint, self::moment($moment)), $moment);
        }
        $this->assertCount(1, $endPoint->dates(), 'the whole week was held from one answer');
        $this->assertSame(1, PublicKeyFetch::cachedKeyCount());
        $before = self::pemAt($endPoint, self::moment('2026-08-30T23:59:00Z'));
        $this->assertNotSame($pem, $before, 'the minute before the week is the earlier week\'s key');
        self::pemAt($endPoint, self::moment('2026-08-24T00:00:00Z'));
        $this->assertCount(2, $endPoint->dates(), 'the earlier week was held from its one answer');
    }

    /**
     * The drift allowance, which keeps minutes near now out of a cache built
     * from confirmed minutes, does not apply to a span the creator stated
     * itself, so live identifiers cost one request per key rather than one
     * per minute.
     */
    public function testARecentMinuteIsServedWhereTheCreatorStatedTheSpan(): void
    {
        $endPoint = $this->endPoint();
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $current = KeyFixtures::schedule()->keyInForce($now);
        if ($current === null || KeyFixtures::schedule()->nextStartAfter($current) === null) {
            $this->markTestSkipped('the fixture schedule has no key after the one in force now');
        }
        self::pemAt($endPoint, $now->modify('-1 minute'));
        self::pemAt($endPoint, $now);
        self::pemAt($endPoint, $now->modify('-10 minutes'));
        $this->assertCount(1, $endPoint->dates(), 'the current key was served for every recent minute from one answer');
    }

    /**
     * An identifier dated just after a key started, but signed with the key
     * before it, verifies, and one dated just before a key started but signed
     * with it verifies too, because the neighbouring key is tried when the
     * selected key fails within the drift allowance of the span's edge.
     * Further from the edge the failure stands. The stand in creator answers
     * with the library's own server side helper, so the loop between the two
     * halves of the library is closed.
     */
    public function testASignatureFailingNearTheEdgeOfASpanIsCheckedAgainstTheNeighbour(): void
    {
        $first = Crypto::new();
        $second = Crypto::new();
        $third = Crypto::new();
        $rotation = self::moment('2026-08-31T00:00:00Z');
        $schedule = PublicKeySchedule::of([
            DatedPublicKey::of($rotation->modify('-7 days'), $first->publicKeyPem()),
            DatedPublicKey::of($rotation, $second->publicKeyPem()),
            DatedPublicKey::of($rotation->modify('+7 days'), $third->publicKeyPem()),
        ]);
        $requests = [];
        $creator = function (string $url, float $timeout) use ($schedule, &$requests): array {
            $requests[] = $url;
            $parameters = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);
            return Endpoints::publicKeyResponseAt($schedule, 'pkcs', $parameters['date'] ?? null);
        };
        $statusOf = fn (Owid $owid): SignatureStatus => PublicKeyFetch::signatureStatusAtUrl(
            $owid,
            'https://creator.test/owid/api/v3/public-key?date=' . Io::minutesSinceBase($owid->date) . '&format=pkcs',
            [],
            $creator
        );
        $late = self::signedAt('creator.test', $rotation->modify('+5 minutes'), $first);
        $this->assertSame(SignatureStatus::SignatureValid, $statusOf($late), 'signed with the earlier key just after the rotation');
        $this->assertCount(2, $requests, 'the selected key and then the earlier key were asked for');
        $early = self::signedAt('creator.test', $rotation->modify('-5 minutes'), $second);
        $this->assertSame(SignatureStatus::SignatureValid, $statusOf($early), 'signed with the later key just before the rotation');
        $this->assertCount(2, $requests, 'both keys are held with their spans');
        $far = self::signedAt('creator.test', $rotation->modify('+20 minutes'), $first);
        $this->assertSame(SignatureStatus::SignatureInvalid, $statusOf($far), 'well inside the later key\'s span');
        $this->assertCount(2, $requests, 'the identifier is further from every edge than clocks may differ');
        $genuine = self::signedAt('creator.test', $rotation->modify('+3 days'), $second);
        $this->assertSame(SignatureStatus::SignatureValid, $statusOf($genuine));
        $forged = self::signedAt('creator.test', $rotation->modify('+3 days'), $third);
        $this->assertSame(SignatureStatus::SignatureInvalid, $statusOf($forged), 'signed with a key not in force at its date');
    }

    /**
     * A transport standing in for a creator that answers each date from the
     * schedule with the span of the key chosen, recording the date of every
     * request. The moment the creator reads as now is fixed so that a request
     * without a date, or with one in the future, is answered the same way on
     * every run.
     *
     * @param array<int, ?string> $asked
     */
    private static function creatorOf(PublicKeySchedule $schedule, array &$asked): callable
    {
        return function (string $url, float $timeout) use ($schedule, &$asked): array {
            $parameters = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);
            $date = $parameters['date'] ?? null;
            $asked[] = is_string($date) ? $date : null;
            return Endpoints::publicKeyResponseAt(
                $schedule,
                'pkcs',
                $date,
                self::moment('2026-09-14T00:00:00Z')
            );
        };
    }

    /** The URL the fetch would use for the identifier at the stand in creator. */
    private static function urlOf(Owid $owid): string
    {
        return 'https://creator.test/owid/api/v3/public-key?date=' . Io::minutesSinceBase($owid->date) . '&format=pkcs';
    }

    /**
     * The neighbouring key is asked for by the minute just beyond the edge of
     * the span the creator stated, not by a minute a fixed distance from the
     * identifier, so a key in force for less than the drift allowance is
     * still the one tried.
     */
    public function testTheNeighbourIsAskedForByTheMinuteJustBeyondTheEdge(): void
    {
        $first = Crypto::new();
        $second = Crypto::new();
        $rotation = self::moment('2026-08-31T00:00:00Z');
        $schedule = PublicKeySchedule::of([
            DatedPublicKey::of($rotation->modify('-7 days'), $first->publicKeyPem()),
            DatedPublicKey::of($rotation, $second->publicKeyPem()),
            DatedPublicKey::of($rotation->modify('+7 days'), Crypto::new()->publicKeyPem()),
        ]);
        $asked = [];
        $creator = self::creatorOf($schedule, $asked);
        $late = self::signedAt('creator.test', $rotation->modify('+5 minutes'), $first);
        $this->assertSame(
            SignatureStatus::SignatureValid,
            PublicKeyFetch::signatureStatusAtUrl($late, self::urlOf($late), [], $creator)
        );
        $rotationMinute = Io::minutesSinceBase($rotation);
        $this->assertSame(
            [(string) ($rotationMinute + 5), (string) ($rotationMinute - 1)],
            $asked,
            'the identifier\'s own minute and then the minute just before the span started'
        );
    }

    /**
     * A key the creator states a start for and no end is in force until
     * further notice as far as the creator has said, so a live identifier
     * dated just after that start which does not verify under it is checked
     * against the key before it, even though the cache holds the key only up
     * to the drift allowance behind now.
     */
    public function testAKeyStatedWithoutAnEndHasNoLaterEdge(): void
    {
        $first = Crypto::new();
        $second = Crypto::new();
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $rotation = $now->modify('-5 minutes');
        $schedule = PublicKeySchedule::of([
            DatedPublicKey::of($rotation->modify('-7 days'), $first->publicKeyPem()),
            DatedPublicKey::of($rotation, $second->publicKeyPem()),
        ]);
        $requests = 0;
        $creator = function (string $url, float $timeout) use ($schedule, &$requests): array {
            $requests++;
            $parameters = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);
            return Endpoints::publicKeyResponseAt($schedule, 'pkcs', $parameters['date'] ?? null);
        };
        $live = self::signedAt('creator.test', $rotation->modify('+2 minutes'), $first);
        $this->assertSame(
            SignatureStatus::SignatureValid,
            PublicKeyFetch::signatureStatusAtUrl($live, self::urlOf($live), [], $creator),
            'a live identifier signed with the key before the current one verifies'
        );
        $this->assertSame(2, $requests, 'the current key and then the key before it were asked for');
    }

    /**
     * A creator whose own statement puts the identifier's date outside the
     * span of the key it answered with has said that key did not sign at
     * that date, so nothing verifying under it leaves the key unavailable
     * rather than the signature not matching. A forgery dated inside the
     * span is still reported as not matching.
     */
    public function testAKeyTheCreatorSaysWasNotInForceLeavesTheSignatureUnjudged(): void
    {
        $first = Crypto::new();
        $second = Crypto::new();
        $stranger = Crypto::new();
        $rotation = self::moment('2026-08-31T00:00:00Z');
        // A creator that ignores the date asked about and answers with the
        // current key and its span whatever the request.
        $ignoring = static fn (string $url, float $timeout): array => [200, Endpoints::publicKeyAnswer(
            $second->publicKeyPem(),
            $rotation,
            $rotation->modify('+7 days'),
            null
        )];
        $earlier = self::signedAt('creator.test', $rotation->modify('-3 days'), $first);
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatusAtUrl($earlier, self::urlOf($earlier), [], $ignoring),
            'the key answered with was not in force at the identifier\'s date'
        );
        $this->assertFalse(PublicKeyFetch::verify($earlier, 'https', [], $ignoring));
        $forged = self::signedAt('creator.test', $rotation->modify('+3 days'), $stranger);
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            PublicKeyFetch::signatureStatusAtUrl($forged, self::urlOf($forged), [], $ignoring),
            'a signature failing under the key in force at its date does not match'
        );
    }

    /**
     * The PEM alone as text is reported as a key this library cannot read rather than used, and so is a span that ends before it starts.
     */
    public function testAnAnswerThatIsNotTheJsonFormIsAKeyThatCannotBeRead(): void
    {
        $endPoint = $this->endPoint(KeyEndPoint::ANSWER_PEM_ONLY);
        $owid = KeyFixtures::identifier();
        $this->assertSame(
            SignatureStatus::InvalidKey,
            PublicKeyFetch::signatureStatusAtUrl($owid, $endPoint->urlFor($owid))
        );
        $contradictory = static fn (string $url, float $timeout): array => [200, json_encode([
            'publicKeySPKI' => KeyFixtures::schedule()->keys()[0]->publicKeyPem,
            'validFrom' => '2026-08-31T00:00:00Z',
            'validTo' => '2026-08-24T00:00:00Z',
        ])];
        $this->assertSame(
            SignatureStatus::InvalidKey,
            PublicKeyFetch::signatureStatusAtUrl($owid, $endPoint->urlFor($owid), [], $contradictory)
        );
    }

    /**
     * The domain arrives inside an OWID, which came from outside, so a value
     * that would change the shape of the URL rather than name a host in it is
     * refused before any request is made.
     */
    public function testADomainThatIsNotADomainNameIsRefusedBeforeAnyRequest(): void
    {
        $buffer = '';
        Io::writeByte($buffer, Version::Version3->asByte());
        Io::writeString($buffer, '51d.es/evil?x=');
        Io::writeDate($buffer, self::identifierDate(), Version::Version3);
        Io::writeByteArray($buffer, '');
        Io::writeSignature($buffer, str_repeat("\0", OwidException::SIGNATURE_LENGTH));
        $result = Owid::tryFromByteArray($buffer);
        if (!$result->ok) {
            // The reader refused the domain first, so nothing can reach the
            // fetch with it, which is the same guarantee one gate earlier.
            $this->assertNull($result->owid);
            return;
        }
        $owid = $result->owid;
        $this->assertNotNull($owid);
        try {
            PublicKeyFetch::publicKeyUrl($owid, 'https');
            $this->fail('the domain should be refused');
        } catch (OwidException $refused) {
            $this->assertStringContainsString('not a domain name', $refused->getMessage());
        }
        $noRequest = function (string $url, float $timeout): array {
            $this->fail('no request should be made for a refused domain');
        };
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatus($owid, 'https', [], $noRequest)
        );
    }

    /**
     * A caller chooses the scheme, and one that reads something other than a
     * creator, such as a file, is refused rather than opened.
     */
    public function testASchemeThatDoesNotMakeAnHttpRequestIsRefused(): void
    {
        $owid = KeyFixtures::identifier();
        $path = realpath(__DIR__ . '/data/identifier.txt');
        $this->assertNotFalse($path);
        $url = 'file:///' . ltrim(str_replace('\\', '/', $path), '/');
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatusAtUrl($owid, $url)
        );
        try {
            PublicKeyFetch::publicKeyPemAtUrl($url, $owid->domain);
            $this->fail('a file scheme is refused');
        } catch (PublicKeyFetchException $refused) {
            $this->assertSame(SignatureStatus::KeyUnavailable, $refused->status());
            $this->assertSame(0, $refused->statusCode());
        }
    }

    public function testAMissingSchemeIsRefused(): void
    {
        $owid = KeyFixtures::identifier();
        foreach (['', '   '] as $scheme) {
            try {
                PublicKeyFetch::publicKeyUrl($owid, $scheme);
                $this->fail('a missing scheme is refused');
            } catch (OwidException $refused) {
                $this->assertStringContainsString('scheme', $refused->getMessage());
            }
        }
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatus($owid, '')
        );
    }

    /**
     * A caller whose environment needs its own HTTP client supplies a
     * transport, which is asked for the URL the library builds and whose
     * answer is held like any other.
     */
    public function testATransportOfTheCallersOwnIsUsed(): void
    {
        $owid = KeyFixtures::identifier();
        $pem = KeyFixtures::schedule()->keyFor($owid)->publicKeyPem;
        $calls = [];
        $transport = function (string $url, float $timeout) use ($pem, &$calls): array {
            $calls[] = [$url, $timeout];
            return [200, Endpoints::publicKeyAnswer($pem, null, null, null)];
        };
        $this->assertSame(
            SignatureStatus::SignatureValid,
            PublicKeyFetch::signatureStatus($owid, 'https', [], $transport)
        );
        $this->assertTrue(PublicKeyFetch::verify($owid, 'https', [], $transport));
        $this->assertSame(
            [[PublicKeyFetch::publicKeyUrl($owid, 'https'), PublicKeyFetch::TIMEOUT_SECONDS]],
            $calls,
            'one request, for the URL the library builds, then the cache'
        );
    }

    /**
     * A creator that states no span and answers with a key other than the
     * one that signed the identifier is reported as a signature that does
     * not match, and verify answers false for it.
     */
    public function testVerifyAnswersTrueOnlyForAGenuineSignature(): void
    {
        $owid = KeyFixtures::identifier();
        $schedule = KeyFixtures::schedule();
        $keys = $schedule->keys();
        $signing = $schedule->keyFor($owid);
        $this->assertNotNull($signing);
        $following = $keys[array_search($signing, $keys, true) + 1];
        $wrongWeek = static fn (string $url, float $timeout): array =>
            [200, Endpoints::publicKeyAnswer($following->publicKeyPem, null, null, null)];
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            PublicKeyFetch::signatureStatus($owid, 'https', [], $wrongWeek),
            "the following week's key did not sign the identifier"
        );
        $this->assertFalse(PublicKeyFetch::verify($owid, 'https', [], $wrongWeek));
    }

    public function testATransportThatThrowsIsKeyUnavailable(): void
    {
        $owid = KeyFixtures::identifier();
        $unreachable = static function (string $url, float $timeout): array {
            throw new Exception('no route');
        };
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatus($owid, 'https', [], $unreachable)
        );
    }

    /** A transport that does not answer with a code and a body is a fault of the transport, not the identifier. */
    public function testATransportThatAnswersBadlyIsKeyUnavailable(): void
    {
        $owid = KeyFixtures::identifier();
        $badly = static fn (string $url, float $timeout): array => ['200', 'not a pair'];
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatus($owid, 'https', [], $badly)
        );
    }

    /** A body beyond the bound is not a key, and is neither held nor decoded. */
    public function testAResponseLargerThanAKeyIsRefused(): void
    {
        $owid = KeyFixtures::identifier();
        $tooLarge = str_repeat('x', PublicKeyFetch::MAXIMUM_RESPONSE_BYTES + 1);
        $oversized = static fn (string $url, float $timeout): array => [200, $tooLarge];
        try {
            PublicKeyFetch::publicKeyPem($owid, 'https', $oversized);
            $this->fail('a body beyond the bound is refused');
        } catch (PublicKeyFetchException $refused) {
            $this->assertSame(SignatureStatus::KeyUnavailable, $refused->status());
            $this->assertSame(200, $refused->statusCode());
        }
        PublicKeyFetch::clearCache();
        $this->assertSame(
            SignatureStatus::KeyUnavailable,
            PublicKeyFetch::signatureStatus($owid, 'https', [], $oversized)
        );
    }
}
