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
        // Keys are held against the URL they were fetched from, and a test
        // that counts requests has to start from nothing held.
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
     * after the identifier was signed, the signature does not match that key,
     * and a genuine identifier reads as a forgery.
     */
    public function testUndatedFetchLeavesAnEarlierWeeksIdentifierUnverified(): void
    {
        $owid = KeyFixtures::identifier();
        $endPoint = $this->endPoint();
        $undated = $endPoint->base . '/owid/api/v3/public-key?format=pkcs';
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            PublicKeyFetch::signatureStatusAtUrl($owid, $undated),
            'an undated request gets the key in force at the request, which did not sign it'
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
     * Keys are held against the URL they came from, which names the minute,
     * so two identifiers from different weeks fetch two different keys and a
     * key held for one week never answers for another. A store keyed by
     * domain alone would hand the second identifier the first one's key.
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
            return [200, "-----BEGIN PUBLIC KEY-----\n" . $minute . "\n-----END PUBLIC KEY-----\n"];
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
        $endPoint = $this->endPoint();
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
        $endPoint = $this->endPoint();
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
        $endPoint = $this->endPoint();
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
     * A date later than now is held against now, because a creator answers a
     * future date with the key in force now and a key held against a minute
     * the creator has not spoken for would be served for that minute after
     * the creator had rotated. Two future dates therefore share one request,
     * and so does a request with no date.
     */
    public function testAFutureDateIsHeldAgainstNow(): void
    {
        $endPoint = $this->endPoint();
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $started = Io::minutesSinceBase($now);
        self::pemAt($endPoint, $now->modify('+7 days'));
        self::pemAt($endPoint, $now->modify('+14 days'));
        PublicKeyFetch::publicKeyPemAtUrl(
            $endPoint->base . '/owid/api/v3/public-key?format=pkcs',
            KeyFixtures::IDENTIFIER_DOMAIN
        );
        if (Io::minutesSinceBase(new DateTimeImmutable('now', new DateTimeZone('UTC'))) !== $started) {
            $this->markTestSkipped('the minute changed during the test, so the calls were not all about the same now');
        }
        $this->assertCount(
            1,
            $endPoint->dates(),
            'two future dates and no date are all now, and now was asked about once'
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
            return [200, $pem];
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

    public function testVerifyAnswersTrueOnlyForAGenuineSignature(): void
    {
        $owid = KeyFixtures::identifier();
        $schedule = KeyFixtures::schedule();
        $keys = $schedule->keys();
        $signing = $schedule->keyFor($owid);
        $this->assertNotNull($signing);
        $following = $keys[array_search($signing, $keys, true) + 1];
        $wrongWeek = static fn (string $url, float $timeout): array => [200, $following->publicKeyPem];
        $this->assertFalse(
            PublicKeyFetch::verify($owid, 'https', [], $wrongWeek),
            "the following week's key did not sign the identifier"
        );
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
