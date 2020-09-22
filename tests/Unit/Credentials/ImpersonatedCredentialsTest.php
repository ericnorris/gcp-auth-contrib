<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use PHPUnit\Framework\TestCase;
use Spatie\Snapshots\MatchesSnapshots;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\ImpersonatedCredentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Tests\MatchesRequestSnapshots;
use ericnorris\GCPAuthContrib\Time;


final class ImpersonatedCredentialsTest extends TestCase {
    use MatchesRequestSnapshots;

    private const NOW = 1596153600;

    private const EXAMPLE_SCOPES_01 = [
        "https://www.googleapis.com/auth/cloud-platform",
    ];

    private const ACCESS_TOKEN_RESPONSE = <<<'RESPONSE'
    {
        "accessToken": "ya29.AHES6ZRN3-HlhAPya30GnW_bHSb_QtAS08i85nHq39HE3C2LTrCARA",
        "expireTime" : "2014-10-02T15:01:23.045123456Z"
    }
    RESPONSE;

    private const AUDIENCE = "https://example.com";

    private const IDENTITY_TOKEN_RESPONSE = <<<'RESPONSE'
    {
        "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNmMzMyYjNlOWI5MjhiZmU1MWJjZjRmOGRhNTQzY2M0YmQ5ZD
        Q3MjQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXpwIjoiZmFrZUBleGFtcGxlLm
        NvbSIsImVtYWlsIjoiZmFrZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE1OTk2MjE5M
        jgsImlhdCI6MTU5OTYxODMyOCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoxMTExMzMz
        NTU1Nzc3OTk5MDAwMDB9.c2lnbmF0dXJlCg"
    }
    RESPONSE;


    public function setUp(): void {
        Time::setForTest(new \DateTimeImmutable("@" . self::NOW));
    }

    public function tearDown(): void {
        Time::resetForTest();
    }

    public function testFetchesAccessToken(): void {
        $responses = [
            new \GuzzleHttp\Psr7\Response(200, [], self::ACCESS_TOKEN_RESPONSE),
        ];


        $fakeClient = $this->makeSnapshotClient($responses);
        $source     = new ImpersonatedCredentialsSourceImpl;
        $fetcher    = new ImpersonatedCredentials($fakeClient, $source, "fake@example.com", ["delegate@example.com"]);

        $got = $fetcher->fetchAccessToken(self::EXAMPLE_SCOPES_01);

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertMatchesSnapshot($got);
    }

    public function testFetchesIdentityToken(): void {
        $responseBody = str_replace("\n", "", self::IDENTITY_TOKEN_RESPONSE);

        $responses = [
            new \GuzzleHttp\Psr7\Response(200, [], $responseBody),
        ];


        $fakeClient = $this->makeSnapshotClient($responses);
        $source     = new ImpersonatedCredentialsSourceImpl;
        $fetcher    = new ImpersonatedCredentials($fakeClient, $source, "fake@example.com", ["delegate@example.com"]);

        $got = $fetcher->fetchIdentityToken(self::AUDIENCE);

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertMatchesSnapshot($got);
    }

}

final class ImpersonatedCredentialsSourceImpl implements Credentials {

    public $expires_in = 0;

    public $timesCalled = 0;

    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        $this->timesCalled++;

        return new FetchAccessTokenResponse(
            "a-token-{$this->timesCalled}",
            time() + $this->expires_in,
            implode(" ", $scopes),
            "Bearer"
        );
    }

    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse {
        throw new \RuntimeException("not implemented");
    }

}
