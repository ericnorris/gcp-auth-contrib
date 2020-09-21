<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use PHPUnit\Framework\TestCase;
use Spatie\Snapshots\MatchesSnapshots;

use ericnorris\GCPAuthContrib\Credentials\ServiceAccountKey;
use ericnorris\GCPAuthContrib\Time;


final class ServiceAccountKeyTest extends TestCase {
    use MatchesSnapshots;

    private const NOW = 1596153600;

    private const VALID_SERVICE_ACCOUNT_KEY = [
        "type"         => "service_account",
        "client_email" => "fake@example.com",
        "private_key"  => self::SERVICE_ACCOUNT_PRIVATE_KEY,
        "project_id"   => "a-project-id",
    ];

    private const SERVICE_ACCOUNT_PRIVATE_KEY = <<<'END'
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpQIBAAKCAQEA5uCYpsUZtyD44BkCHYyVCjrhzeV/U+gg9Yswu0fDapAs5Ost
    qIOt8FNwQzrDlAdymU6B0akkQztP7p/c+HFfNtUtF5iYoIZyc6DUYun0V7/Agi1n
    mnrlz2d2HoIiIf0Ugr5046Vq9nAaa2WekUWd5+WdMN2tJcgFZJYryBaddyu4vQxm
    kx/8GzruqH+qDT8h38Aib0YJwmfwlOknQftN3a5vhKDdZZZZWT8X++MtLDNjYadC
    o+OqP110ak3FNYX7A6UEAHYQM419inXuPTNQ3tXjGGzArvzBhEtpubPVOfyYn9GS
    AV6Kw3UCSuSAYf49nspb6XI8CAGMc8ef5j32rQIDAQABAoIBAE217Uu87gHo1DxB
    zqd5iTTvSs/N3oS0jlt3pUh0SD9XFfVbf3vIDsTkoNXQMsJhm14kwad7YhxLG4V7
    Q5pQNrczG8FkeIMXnfBzgulkS/05KqfmdofVtAKSlXyBWtHL6Jp1VszFAfK/GvVp
    N+033IWQkM9A3iXoZIBN16C6k/fnGK+4DLavgazBx7yr9+hEUcXJtKNjLO6ZTBdN
    OcCH0d6RTj+f/lAEQw7aqWlP3r+51Ge8bJWKl+G0cwyePe/eid30XR498+iull1l
    WoVebJ0HJ7bzGNKIzYEZZ+8XsSNUnh7e6GzvOWoEJIjhOxCRnJVp40khxs5X+sfV
    2AtZEHUCgYEA/eLcJjN62iMVImPJ826K1k6Sk565meq/quJzkTclt9reWJga/aq2
    iQ+iCEG1tbt29t5PCFkVQjwAzBV6yYjs2zIl1//Uflux8+4L6I1D93yX6M/zkU5f
    uislfRHVDRxIcttHAac4CI6TKe+t3kurgYLXLPuANyE6DsxYfChUNNMCgYEA6Myx
    1J89PQeZvXpjMYFOOgTLoL5gfuicIwOBs4uxONziiEvbcKrvAQc5IyGrfLa+ZS7/
    7mrkiFeE8TMqYygnU4x9RI1YBonCmOsiwWHMKYqtbP/rawhZKSrDVmiUYLmEvCGU
    hIozP0PG4TjyI8E/uUEF8N1KiHUD/M2epyJX9n8CgYEAw68kgekx6ooZ0wzY7mEo
    b6/V+CPh6Elwe7TY4HeCAeiXce+i9hurX48GE5kaBj28nuCQR93prchz0NlJb6ay
    8OwBETAlR1NDoMC8uvyPA2Ur7QzDLh8bV3HEDlc9QEKpcKWkYBjT7nx931fWSj1G
    rqb7VLdwho18o0VLej7XUHMCgYEAie2FSxFRqhAPwZh6nsEaxPtEXieNaoOMxp30
    QZl5VdRhDxnKmPVdh8Fs0+jF/q0TH0X6cpq4biNUa8fBzF/k9PZe3bfUuIL0Xb+q
    puK3oME+QT9bjt2yXdatR0vM5YXlI8XNhb2P4WLZuWUQ6ag8hhkFWRDzcOfLhgOZ
    hTKu5ScCgYEAl6P9gHadb0Kldm/HGSd2PWls3zLAadOxSfBgmj7F0aXKstnGHO7h
    3JI5JxfqtGKMuLZKOCtIkk8OUJr8aG2LoKp36ytncBf0Q0XCuvSgzeiSTZ/aiAUD
    oPZ0mJss/pEQtAqoOEFEdZJIBrVPF2d8kl51gufoqD4UnV7/LOS+ID4=
    -----END RSA PRIVATE KEY-----
    END;

    public function setUp(): void {
        Time::setForTest(new \DateTimeImmutable("@" . self::NOW));
    }

    public function tearDown(): void {
        Time::resetForTest();
    }

    /**
     * @dataProvider serviceAccountKeyProvider
     */
    public function testDetectsServiceAccountKey(array $serviceAccountKey, bool $valid): void {
        if (!$valid) {
            $this->expectException(\InvalidArgumentException::class);
        }

        $fetcher = new ServiceAccountKey(new \GuzzleHttp\Client, $serviceAccountKey);

        $this->assertNotNull($fetcher);
    }

    public function testAssertClaims(): void {
        $fetcher = new ServiceAccountKey(new \GuzzleHttp\Client, self::VALID_SERVICE_ACCOUNT_KEY);

        $assertClaimsMethod = new \ReflectionMethod(ServiceAccountKey::class, "assertClaims");
        $assertClaimsMethod->setAccessible(true);

        $got = $assertClaimsMethod->invoke($fetcher, ["claim-1" => "value"]);

        $this->assertMatchesSnapshot($got);
    }

    public function serviceAccountKeyProvider(): array {
        $wrongType = [
            "type" => "not_service_account",
        ] + self::VALID_SERVICE_ACCOUNT_KEY;

        $missingClientEmail = [
            "client_email" => null,
        ] + self::VALID_SERVICE_ACCOUNT_KEY;

        $missingPrivateKey = [
            "private_key" => null,
        ] + self::VALID_SERVICE_ACCOUNT_KEY;

        $missingProjectID = [
            "project_id" => null,
        ] + self::VALID_SERVICE_ACCOUNT_KEY;

        return [
            [$wrongType, false],
            [$missingClientEmail, false],
            [$missingPrivateKey, false],
            [$missingProjectID, false],
            [self::VALID_SERVICE_ACCOUNT_KEY, true]
        ];
    }

    protected function getSnapshotDirectory(): string {
        return __DIR__ . "/../../../snapshots";
    }

}
