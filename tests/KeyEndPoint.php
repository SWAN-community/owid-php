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
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\PublicKeyFetch;

/**
 * A stand in for the public key end point of a creator, answering the way
 * the cloud controller does and serving the real published 51d.es schedule.
 *
 * The live end point answers 401 without a credential, so the tests stand
 * this up on the loopback address instead, which is what the Java, Rust and
 * Go ports do for the same reason. It runs as PHP's own built in web server
 * in a second process, with key_end_point_router.php answering every request.
 *
 * A request naming a date is served the key that was in force then, a
 * request without one is served the key in force at the moment of the
 * request, a date after that moment is read as that moment, and a date the
 * schedule does not reach is a 404. That is how the cloud answers, and the
 * moment of the request is fixed at REQUEST_MOMENT so the tests are
 * repeatable. The date parameter of every request is recorded, so a test can
 * say what went over the wire rather than only what the URL builder returned.
 */
final class KeyEndPoint
{
    /**
     * The moment the end point treats as now, ten days after the fixture
     * identifier was signed and in the week that followed. Every port's stand
     * in uses this moment. An undated request is therefore served a key other
     * than the one that signed the fixture, exactly as it would be against
     * the live creator in that week.
     */
    public const REQUEST_MOMENT = '2026-09-14T00:00:00Z';

    /** The published schedule, chosen by the date requested. */
    public const ANSWER_SCHEDULE = 'schedule';

    /** Text shaped like a PEM that no key can be read out of. */
    public const ANSWER_BROKEN_KEY = 'broken-key';

    /** A redirect to a host that is not the creator, which a client must not follow. */
    public const ANSWER_REDIRECT = 'redirect';

    /** The value the router records for a request that carried no date. */
    public const NO_DATE = '-';

    /** @var resource */
    private $process;

    /**
     * @param resource $process
     */
    private function __construct(
        $process,
        public readonly string $base,
        private readonly string $log
    ) {
        $this->process = $process;
    }

    /** The moment the end point treats as now. */
    public static function requestMoment(): DateTimeImmutable
    {
        return new DateTimeImmutable(self::REQUEST_MOMENT, new DateTimeZone('UTC'));
    }

    /**
     * Starts an end point serving what the answer says, and waits until it
     * accepts connections.
     */
    public static function start(string $answer = self::ANSWER_SCHEDULE): self
    {
        $port = self::freePort();
        $log = tempnam(sys_get_temp_dir(), 'owid-key-end-point-');
        if ($log === false) {
            throw new RuntimeException('could not make the request log');
        }
        $null = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['file', $null, 'a'],
            2 => ['file', $null, 'a'],
        ];
        $environment = getenv();
        $environment['OWID_KEY_ANSWER'] = $answer;
        $environment['OWID_KEY_LOG'] = $log;
        $process = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/key_end_point_router.php'],
            $descriptors,
            $pipes,
            __DIR__,
            $environment
        );
        if ($process === false) {
            throw new RuntimeException('could not start the stand in');
        }
        fclose($pipes[0]);
        $endPoint = new self($process, 'http://127.0.0.1:' . $port, $log);
        for ($attempt = 0; $attempt < 100; $attempt++) {
            $socket = @fsockopen('127.0.0.1', $port, $errorCode, $errorText, 0.25);
            if ($socket !== false) {
                fclose($socket);
                return $endPoint;
            }
            usleep(50000);
        }
        $endPoint->stop();
        throw new RuntimeException('the stand in did not start listening');
    }

    /** Stops the end point, after which its address refuses connections. */
    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
        @unlink($this->log);
    }

    /**
     * The URL a fetch would use, with the creator domain replaced by this end
     * point. The path and the query are the ones the library builds, so what
     * is under test is the real URL rather than a copy of it.
     */
    public function urlFor(Owid $owid): string
    {
        $built = PublicKeyFetch::publicKeyUrl($owid, 'http');
        $at = strpos($built, $owid->domain);
        if ($at === false) {
            throw new RuntimeException('the URL should name the domain');
        }
        return $this->base . substr($built, $at + strlen($owid->domain));
    }

    /**
     * The date parameter of every request served so far, in order, with null
     * for a request that carried no date.
     *
     * @return array<int, string|null>
     */
    public function dates(): array
    {
        $text = file_get_contents($this->log);
        if ($text === false || $text === '') {
            return [];
        }
        $dates = [];
        foreach (explode("\n", rtrim($text, "\n")) as $line) {
            $dates[] = $line === self::NO_DATE ? null : $line;
        }
        return $dates;
    }

    /** A port nothing is listening on, found by binding to port 0. */
    private static function freePort(): int
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorText);
        if ($server === false) {
            throw new RuntimeException('could not find a free port: ' . $errorText);
        }
        $name = stream_socket_get_name($server, false);
        fclose($server);
        if ($name === false) {
            throw new RuntimeException('could not read the bound port');
        }
        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }
}
