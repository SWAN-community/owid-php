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

use PHPUnit\Framework\TestCase;

/**
 * Runs the PHP examples in the README so that documentation naming a method
 * that does not exist fails the build.
 *
 * The examples are taken in the order they appear and run as one script,
 * because the later ones use the creator and the OWID the first one makes,
 * which is how a reader follows them. Checks are appended to the end so that
 * the examples are shown to do what the surrounding text says they do, rather
 * than merely to run.
 */
final class ReadmeTest extends TestCase
{
    /**
     * Returns the contents of every fenced php block in the README, in order.
     *
     * @return array<int, string>
     */
    private static function examples(): array
    {
        $readme = file_get_contents(__DIR__ . '/../README.md');
        self::assertNotFalse($readme, 'the README should be readable');
        $matches = [];
        preg_match_all('/```php\r?\n(.*?)```/s', $readme, $matches);
        return $matches[1];
    }

    /**
     * Every documented example compiles and runs, and the identifier the first
     * one creates reads back and verifies.
     */
    public function testReadmeExamplesRun(): void
    {
        $examples = self::examples();
        $this->assertGreaterThanOrEqual(
            4,
            count($examples),
            'the README should still carry its examples'
        );

        $checks = <<<'PHP'

        if (!$result->ok) {
            fwrite(STDERR, 'the example identifier did not read back');
            exit(1);
        }
        if ($valid !== true) {
            fwrite(STDERR, 'the example identifier did not verify');
            exit(1);
        }
        if ($status !== SignatureStatus::SignatureValid) {
            fwrite(STDERR, 'the example status was ' . $status->value);
            exit(1);
        }
        if (count($identifiers) !== 2) {
            fwrite(STDERR, 'the frame walk found ' . count($identifiers));
            exit(1);
        }
        if ($offset !== strlen($framedBuffer)) {
            fwrite(STDERR, 'the frame walk stopped at ' . $offset);
            exit(1);
        }
        PHP;

        $script = "<?php\n" .
            'require ' . var_export(__DIR__ . '/../vendor/autoload.php', true) . ";\n" .
            implode("\n", $examples) . $checks . "\n";

        // tempnam makes the file, so both names are removed afterwards
        // rather than leaving the empty one behind on every run.
        $reserved = tempnam(sys_get_temp_dir(), 'owid-readme-');
        $path = $reserved . '.php';
        file_put_contents($path, $script);
        try {
            $output = [];
            $code = 0;
            exec(
                escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($path) . ' 2>&1',
                $output,
                $code
            );
            $this->assertSame(
                0,
                $code,
                "the README examples failed:\n" . implode("\n", $output)
            );
            $this->assertSame(
                [],
                $output,
                'the README examples should run without output'
            );
        } finally {
            unlink($path);
            unlink($reserved);
        }
    }
}
