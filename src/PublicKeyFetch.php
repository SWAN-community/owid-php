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

use DateTimeZone;
use DateTimeImmutable;
use Exception;

/**
 * Fetches the signing public key of a creator from the well known end point
 * on the domain the OWID carries, asking for the key that was in force on the
 * date the OWID carries.
 *
 * The end point is /owid/api/v{n}/public-key?date={minutes}&format=pkcs,
 * where the version in the path is the version byte of the OWID being checked
 * rather than a constant, and the minutes are counted from 2020-01-01 in the
 * same way the OWID stores the date. Creators rotate weekly, so without the
 * date only identifiers signed since the most recent rotation can be verified
 * and every older one reads as not matching. A creator that ignores the
 * parameter returns its current key, so every identifier it signed under an
 * earlier key reads as not matching, which is why a creator that rotates its
 * key has to honour the date.
 *
 * Only the HTTP stream wrapper PHP ships with is used, so the library keeps
 * its promise of no external dependency. This class is the one place in the
 * library that reaches the network, nothing else loads it, and every method
 * takes a transport of the caller's own for a host where remote stream access
 * is turned off or another client is wanted.
 *
 * The Java port answers the same question with PublicKeyFetch, the Rust port
 * with Owid::verify_status and the Go port with SignatureStatusFromDomain.
 */
final class PublicKeyFetch
{
    /** How long to wait for the connection and then for the response, in seconds. */
    public const TIMEOUT_SECONDS = 10.0;

    /**
     * The most keys held before the cache is emptied and filled again, across
     * every creator. A bound is needed because a verifier sees identifiers
     * from many domains and many weeks, and an unbounded store would grow for
     * as long as the process runs.
     */
    public const MAXIMUM_CACHED_KEYS = 1024;

    /**
     * How far a creator's clock may run ahead of or behind this one's, in
     * minutes. A minute closer to now than this, or later, is asked about
     * rather than served from the cache, and is not held.
     *
     * A creator reads a date later than its own now as now, and answers with
     * the key in force now. Within this window this process cannot tell
     * whether the creator read the minute as its past or as its present, so
     * the answer says nothing certain about the minute. An identifier signed
     * just after a rotation by a creator whose clock runs ahead would
     * otherwise be served the old key from a span confirmed up to now, and
     * would read as not matching until this clock caught up. Identifiers
     * dated within the window are asked about once per minute per creator,
     * as they always were, and every older identifier is served from the
     * spans.
     */
    public const CLOCK_DRIFT_ALLOWANCE_MINUTES = 15;

    /**
     * The most bytes accepted from a response. A public key PEM is a few
     * hundred bytes, so a body beyond this is not a key and is not held.
     */
    public const MAXIMUM_RESPONSE_BYTES = 65536;

    /**
     * The schemes that make an HTTP request. A caller chooses the scheme, and
     * one that reads something other than a creator, such as file, is refused
     * rather than opened.
     */
    private const ACCEPTED_SCHEMES = ['http', 'https'];

    /**
     * Keys already fetched, by the creator's key end point, which is the key
     * URL without its date. Each end point holds the keys the creator has
     * answered with, each with the span of minutes the creator has confirmed
     * it for, as the earliest and latest minute.
     *
     * The specification asks implementations to cache so that verifying many
     * identifiers does not mean repeating requests to another processor. The
     * key URL carries the date of the identifier being verified, in minutes,
     * and a creator's key changes on the order of a week. Keyed by the whole
     * URL, as this cache once was, two identifiers signed a minute apart
     * never shared an entry, so a hundred identifiers over a hundred minutes
     * made a hundred requests for one key. Keyed by end point and span, an
     * identifier dated between two minutes the creator has already answered
     * for is verified without a request. A key is in force from the start of
     * its period until the next key starts, so a key the creator confirms at
     * two minutes was in force at every minute between them.
     *
     * @var array<string, array<int, array{pem: string, first: int, last: int}>>
     */
    private static array $cache = [];

    /** How many keys are held across every end point. */
    private static int $heldKeys = 0;

    private function __construct()
    {
    }

    /**
     * Returns the URL of the public key end point for the OWID, using the
     * scheme provided, which is normally https.
     *
     * The date the OWID carries is sent as the date parameter, counted in
     * whole minutes from 2020-01-01, so that a creator which rotates its key
     * returns the key that was in force when this OWID was signed. The
     * parameter is left out where the date cannot be counted, which no OWID
     * this library reads can be, because the wire format cannot hold such a
     * date.
     *
     * @throws OwidException when the scheme is missing, or the domain the
     *                       OWID carries is not a domain name this library
     *                       will put in a URL.
     */
    public static function publicKeyUrl(Owid $owid, string $scheme): string
    {
        if (trim($scheme) === '') {
            throw new OwidException('the scheme is missing');
        }
        self::checkDomain($owid->domain);
        $minutes = Io::minutesSinceBase($owid->date);
        $query = $minutes >= 0
            ? 'date=' . $minutes . '&format=pkcs'
            : 'format=pkcs';
        return $scheme . '://' . $owid->domain
            . Endpoints::publicKeyPath($owid->version) . '?' . $query;
    }

    /**
     * Returns the public key PEM of the creator of the OWID, for the date the
     * OWID carries.
     *
     * A transport is a callable taking the URL and the timeout in seconds and
     * returning the response code and the body as a two element array. It
     * throws an Exception where no response could be obtained at all.
     *
     * @throws PublicKeyFetchException when the key could not be obtained,
     *                                 with the status to report for the
     *                                 identifier.
     * @throws OwidException           when the scheme or the domain is not
     *                                 usable.
     */
    public static function publicKeyPem(
        Owid $owid,
        string $scheme,
        ?callable $transport = null
    ): string {
        return self::publicKeyPemAtUrl(
            self::publicKeyUrl($owid, $scheme),
            $owid->domain,
            $transport
        );
    }

    /**
     * Says whether the signature on the OWID is genuine, fetching the key
     * that was in force when the OWID was signed from the creator domain.
     *
     * A key that cannot be fetched is SignatureStatus::KeyUnavailable and one
     * that arrives in a form this library cannot read is
     * SignatureStatus::InvalidKey. Neither is SignatureStatus::SignatureInvalid,
     * because an outage or a badly served key leaves the signature unjudged,
     * and reporting either as invalid would read as an attack.
     *
     * @param array<int, Owid> $others the other OWIDs that were signed
     *                                 together with this one, in the same
     *                                 order as when signed
     */
    public static function signatureStatus(
        Owid $owid,
        string $scheme,
        array $others = [],
        ?callable $transport = null
    ): SignatureStatus {
        try {
            $url = self::publicKeyUrl($owid, $scheme);
        } catch (OwidException $refused) {
            return SignatureStatus::KeyUnavailable;
        }
        return self::signatureStatusAtUrl($owid, $url, $others, $transport);
    }

    /**
     * Returns true only when the signature verifies under the key the creator
     * served for the date the OWID carries. Every other outcome, a signature
     * that does not match included, is false, so ask signatureStatus where the
     * difference changes what the caller does.
     *
     * @param array<int, Owid> $others
     */
    public static function verify(
        Owid $owid,
        string $scheme,
        array $others = [],
        ?callable $transport = null
    ): bool {
        return self::signatureStatus($owid, $scheme, $others, $transport)
            === SignatureStatus::SignatureValid;
    }

    /**
     * Empties the cache of keys already fetched, so that the next
     * verification of any identifier asks the creator again. This is how a
     * long running process drops a key it has learned it should no longer
     * trust, after a creator rotates its key following a compromise, and how
     * a test starts from a known state.
     */
    public static function clearCache(): void
    {
        self::$cache = [];
        self::$heldKeys = 0;
    }

    /**
     * How many keys the cache holds, for the tests.
     *
     * @internal
     */
    public static function cachedKeyCount(): int
    {
        return self::$heldKeys;
    }

    /**
     * The work signatureStatus does once the URL is known, kept apart so that
     * the tests drive the real fetch against a key end point the tests can
     * stand up locally rather than against a near copy of the fetch.
     *
     * @internal
     *
     * @param array<int, Owid> $others
     */
    public static function signatureStatusAtUrl(
        Owid $owid,
        string $url,
        array $others = [],
        ?callable $transport = null
    ): SignatureStatus {
        try {
            $pem = self::publicKeyPemAtUrl($url, $owid->domain, $transport);
        } catch (PublicKeyFetchException $failed) {
            return $failed->status();
        } catch (OwidException $refused) {
            return SignatureStatus::KeyUnavailable;
        }
        return $owid->signatureStatus($pem, $others);
    }

    /**
     * Fetches the PEM at the URL, answering from the cache where the creator
     * has already confirmed a key for the minute the URL names.
     *
     * @internal
     *
     * @throws PublicKeyFetchException when the key could not be obtained.
     */
    public static function publicKeyPemAtUrl(
        string $url,
        string $domain,
        ?callable $transport = null
    ): string {
        $endPoint = self::endPointOf($url);
        $minute = self::minuteOf($url);
        $held = $minute === null ? null : self::heldPem($endPoint, $minute);
        if ($held !== null) {
            return $held;
        }
        $pem = self::read($url, $domain, $transport);
        if ($minute !== null) {
            self::hold($endPoint, $minute, $pem);
        }
        return $pem;
    }

    /**
     * The key URL without its query, which names the scheme, the creator and
     * the version, and so the key end point being asked.
     */
    private static function endPointOf(string $url): string
    {
        $query = strpos($url, '?');
        return $query === false ? $url : substr($url, 0, $query);
    }

    /**
     * The minute the cache reads the URL as asking about, or null where the
     * cache must not be used for the request.
     *
     * The date parameter where the URL carries one and it is at least
     * CLOCK_DRIFT_ALLOWANCE_MINUTES behind now. A request without a date asks
     * for the key in force now, and one dated within the allowance, or later,
     * may be read by the creator as its present rather than as the minute
     * named, so neither is served from the cache nor held in it.
     */
    private static function minuteOf(string $url): ?int
    {
        $now = Io::minutesSinceBase(
            new DateTimeImmutable('now', new DateTimeZone('UTC'))
        );
        $parameters = [];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);
        $date = $parameters['date'] ?? null;
        if (is_string($date) && $date !== '' && ctype_digit($date)) {
            $minute = (int) $date;
            if ($minute <= $now - self::CLOCK_DRIFT_ALLOWANCE_MINUTES) {
                return $minute;
            }
        }
        return null;
    }

    /**
     * The key held for the end point whose confirmed span covers the minute,
     * or null where no held key does.
     */
    private static function heldPem(string $endPoint, int $minute): ?string
    {
        foreach (self::$cache[$endPoint] ?? [] as $key) {
            if ($key['first'] <= $minute && $minute <= $key['last']) {
                return $key['pem'];
            }
        }
        return null;
    }

    /**
     * Records that the creator answered the minute with the key.
     *
     * A key already held for the end point has its span widened to take in
     * the minute. A key not held before is added, emptying the cache first
     * when it is full, because the domains and dates asked about come from
     * the identifiers presented to this process and the cache must not grow
     * on their input.
     */
    private static function hold(string $endPoint, int $minute, string $pem): void
    {
        foreach (self::$cache[$endPoint] ?? [] as $index => $key) {
            if ($key['pem'] === $pem && self::widen($endPoint, $index, $minute)) {
                return;
            }
        }
        if (self::$heldKeys >= self::MAXIMUM_CACHED_KEYS) {
            self::$cache = [];
            self::$heldKeys = 0;
        }
        self::$cache[$endPoint][] = ['pem' => $pem, 'first' => $minute, 'last' => $minute];
        self::$heldKeys++;
    }

    /**
     * Widens the span of the held key at the index to take in the minute,
     * and says whether the minute is now within it.
     *
     * The span is not widened across a minute the creator has answered with
     * another key for, because that would mean the creator had gone back to
     * a key it had left, and the minutes between the two spans are then not
     * this key's to claim. The key is held again as a separate span instead.
     */
    private static function widen(string $endPoint, int $index, int $minute): bool
    {
        $key = self::$cache[$endPoint][$index];
        if ($key['first'] <= $minute && $minute <= $key['last']) {
            return true;
        }
        $from = min($minute, $key['first']);
        $to = max($minute, $key['last']);
        foreach (self::$cache[$endPoint] as $otherIndex => $other) {
            if ($otherIndex !== $index && $other['last'] > $from && $other['first'] < $to) {
                return false;
            }
        }
        if ($minute < $key['first']) {
            self::$cache[$endPoint][$index]['first'] = $minute;
        } else {
            self::$cache[$endPoint][$index]['last'] = $minute;
        }
        return true;
    }

    /**
     * Performs the request and returns the body as text.
     *
     * @throws PublicKeyFetchException
     */
    private static function read(string $url, string $domain, ?callable $transport): string
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, self::ACCEPTED_SCHEMES, true)) {
            // A scheme the caller chose that does not make an HTTP request,
            // such as file. Refused before anything is opened, because every
            // route into this class promises to ask a creator and nothing
            // else.
            throw new PublicKeyFetchException(
                'the scheme used for domain ' . self::quoted($domain)
                    . ' does not make an HTTP request',
                SignatureStatus::KeyUnavailable,
                $domain
            );
        }
        try {
            $answer = ($transport ?? self::streamTransport(...))($url, self::TIMEOUT_SECONDS);
        } catch (Exception $failed) {
            // A refused connection, a name that does not resolve and a
            // timeout all arrive here, and all of them mean the signature was
            // never examined.
            throw new PublicKeyFetchException(
                'the public key could not be fetched from domain '
                    . self::quoted($domain),
                SignatureStatus::KeyUnavailable,
                $domain,
                0,
                $failed
            );
        }
        if (
            !is_array($answer) || count($answer) !== 2
            || !is_int($answer[0]) || !is_string($answer[1])
        ) {
            throw new PublicKeyFetchException(
                'the transport did not return a response code and a body '
                    . 'for domain ' . self::quoted($domain),
                SignatureStatus::KeyUnavailable,
                $domain
            );
        }
        [$code, $body] = $answer;
        if ($code !== 200) {
            throw new PublicKeyFetchException(
                'domain ' . self::quoted($domain) . " returned code '" . $code
                    . "' for the public key",
                SignatureStatus::KeyUnavailable,
                $domain,
                $code
            );
        }
        if (strlen($body) > self::MAXIMUM_RESPONSE_BYTES) {
            throw new PublicKeyFetchException(
                'domain ' . self::quoted($domain)
                    . ' returned more than a key for the public key',
                SignatureStatus::KeyUnavailable,
                $domain,
                $code
            );
        }
        return $body;
    }

    /**
     * The transport used unless the caller supplies one, being the HTTP
     * stream wrapper. A refusal carrying a response code is returned as that
     * code, and only the failure to obtain any response at all is thrown.
     *
     * @return array{0: int, 1: string}
     *
     * @throws Exception when no response could be obtained.
     */
    private static function streamTransport(string $url, float $timeout): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: text/plain\r\n",
                'timeout' => $timeout,
                'ignore_errors' => true,
                // Never followed. The wrapper would otherwise reopen
                // whatever Location names, any host and plain http
                // included, and a creator whose domain answered 302
                // would have that other place's key trusted as its
                // own. With ignore_errors the 3xx comes back as the
                // response code and is read as the key being
                // unavailable, which is what it is.
                'follow_location' => 0,
            ],
        ]);
        $http_response_header = [];
        $body = @file_get_contents(
            $url,
            false,
            $context,
            0,
            self::MAXIMUM_RESPONSE_BYTES + 1
        );
        if ($body === false) {
            $reason = error_get_last();
            throw new Exception(
                $reason['message'] ?? 'no response was obtained'
            );
        }
        return [self::responseCode($http_response_header), $body];
    }

    /**
     * The code of the last response in the headers the stream wrapper
     * collected, which is the one after any redirect, or 0 where there is no
     * status line at all.
     *
     * @param array<int, string> $headers
     */
    private static function responseCode(array $headers): int
    {
        $code = 0;
        foreach ($headers as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $found) === 1) {
                $code = (int) $found[1];
            }
        }
        return $code;
    }

    /**
     * Refuses a domain that would change the shape of the URL rather than
     * name a host in it.
     *
     * The domain arrives inside an OWID, which came from outside, so the text
     * is not the library's own. Letters, digits, dots and hyphens are all a
     * domain name needs, and anything else could add a query, a fragment, a
     * port, credentials or a path and send the request somewhere other than
     * the creator.
     *
     * @throws OwidException
     */
    private static function checkDomain(string $domain): void
    {
        if ($domain === '') {
            throw new OwidException('the OWID carries no domain');
        }
        // \z rather than $, because $ also matches before a final line
        // feed and would let "51d.es\n" through into the URL.
        if (preg_match('/^[A-Za-z0-9.-]+\z/', $domain) !== 1) {
            // The domain is not repeated back, because the text arrived from
            // outside and a refusal is often logged.
            throw new OwidException(
                'the domain in the OWID is not a domain name this library '
                    . 'will request a key from'
            );
        }
    }

    /** The value in single quotes, for a message. */
    private static function quoted(string $value): string
    {
        return "'" . $value . "'";
    }
}
