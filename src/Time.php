<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib;


final class Time {

    /** @var \DateTimeImmutable|null */
    private static $fakeNow;


    public static function now(): \DateTimeImmutable {
        if (!empty(self::$fakeNow)) {
            return self::$fakeNow;
        }

        return new \DateTimeImmutable;
    }

    public static function calculateExpiresAt(int $expiresIn): \DateTimeImmutable {
        return self::now()->add(\DateInterval::createFromDateString("{$expiresIn} seconds"));
    }

    public static function setForTest(\DateTimeImmutable $now): void {
        self::$fakeNow = $now;
    }

    public static function freezeForTest(): void {
        self::setForTest(self::now());
    }

    public static function resetForTest(): void {
        self::$fakeNow = null;
    }

}
