<?php
/**
 * Modified from
 * https://github.com/googleapis/google-cloud-php-core/blob/f9e7421beac89fd7d9006a13a6b39b89dd86c92e/src/TimeTrait.php,
 * see below license.
 *
 * Copyright 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace ericnorris\GCPAuthContrib\Internal\Contracts;


trait ParsesRFC3339Timestamps
{
    /**
     * Parses an RFC3339 formatted date time.
     *
     * @param string $timestamp A string representation of a timestamp, encoded in RFC 3339 format
     *        (YYYY-MM-DDTHH:MM:SS.000000[000]TZ).
     *
     * @return \DateTimeImmutable
     */
    private function parseRFC3339Timestamp($timestamp): \DateTimeImmutable
    {
        $nanoRegex = '/\d{4}-\d{1,2}-\d{1,2}T\d{1,2}\:\d{1,2}\:\d{1,2}(?:(\.\d{1,}))?/';

        if (\preg_match($nanoRegex, $timestamp, $matches)) {
            $fractionalSeconds = $matches[1] ?? "";

            if (strlen($fractionalSeconds) > 7) {
                $clampedFractional = substr($fractionalSeconds, 0, 7);

                $timestamp = \str_replace($fractionalSeconds, $clampedFractional, $timestamp);
            }
        }

        return new \DateTimeImmutable($timestamp);
    }

}
