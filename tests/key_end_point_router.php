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

/**
 * The router script PHP's built in web server runs for KeyEndPoint, answering
 * every request the way the cloud's public key end point does. See
 * KeyEndPoint for the rules. Started by KeyEndPoint::start and never by hand.
 */

require __DIR__ . '/../vendor/autoload.php';

use SwanCommunity\Owid\Endpoints;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Tests\KeyEndPoint;
use SwanCommunity\Owid\Tests\KeyFixtures;

$answer = getenv('OWID_KEY_ANSWER');
if ($answer === false || $answer === '') {
    $answer = KeyEndPoint::ANSWER_SCHEDULE;
}
$log = getenv('OWID_KEY_LOG');
$date = isset($_GET['date']) && is_string($_GET['date']) ? $_GET['date'] : null;
if ($log !== false && $log !== '') {
    file_put_contents(
        $log,
        ($date ?? KeyEndPoint::NO_DATE) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

if ($answer === KeyEndPoint::ANSWER_REDIRECT) {
    http_response_code(302);
    header('Location: http://elsewhere.invalid/key.pem');
    return;
}

if ($answer === KeyEndPoint::ANSWER_BROKEN_KEY) {
    // Shaped like a PEM, with a body no key can be read out of. It is sent as the JSON form without the check a creator applies, because that check is what catches it.
    header('Content-Type: application/json');
    echo json_encode([
        'format' => 'spki',
        'publicKey' => "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n",
        'validFrom' => null,
        'validTo' => null,
    ]);
    return;
}

$moment = KeyEndPoint::requestMoment();
$asked = $moment;
if ($date !== null) {
    if (preg_match('/^[0-9]{1,10}$/', $date) !== 1) {
        // A date that is not a number is refused, as the cloud refuses it.
        http_response_code(400);
        return;
    }
    $asked = Io::baseDate()->modify('+' . $date . ' minutes');
    if ($asked === false || $asked > $moment) {
        $asked = $moment;
    }
}
$key = KeyFixtures::schedule()->keyInForce($asked);
if ($key === null) {
    http_response_code(404);
    return;
}
if ($answer === KeyEndPoint::ANSWER_PEM_ONLY) {
    header('Content-Type: text/plain');
    echo $key->publicKeyPem;
    return;
}
header('Content-Type: application/json');
if ($answer === KeyEndPoint::ANSWER_SPANLESS) {
    echo Endpoints::publicKeyAnswer($key->publicKeyPem, null, null, null);
    return;
}
// The answer the library's own server side helper builds, so the client is
// tested against what a creator built on it sends, with the format the
// request asked for passed through so the request the client makes is the
// one judged.
[$status, $body] = Endpoints::publicKeyResponseAt(KeyFixtures::schedule(), $_GET['format'] ?? null, $date, $moment);
http_response_code($status);
echo $body;
