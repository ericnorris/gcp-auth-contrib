<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use PHPUnit\Framework\TestCase;
use Spatie\Snapshots\MatchesSnapshots;

use ericnorris\GCPAuthContrib\Credentials\MetadataServerCredentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Tests\MatchesRequestSnapshots;
use ericnorris\GCPAuthContrib\Time;


final class MetadataServerCredentialsTest extends TestCase {
    use MatchesRequestSnapshots;

    private const NOW = 1596153600;

    private const ACCESS_TOKEN_RESPONSE = <<<'RESPONSE'
    {
        "access_token": "ya29.AHES6ZRN3-HlhAPya30GnW_bHSb_QtAS08i85nHq39HE3C2LTrCARA",
        "expires_in"  : 3600,
        "token_type"  : "Bearer"
    }
    RESPONSE;

    private const AUDIENCE = "https://example.com";

    private const IDENTITY_TOKEN_RESPONSE = <<<'RESPONSE'
    eyJhbGciOiJSUzI1NiIsImtpZCI6IjNmMzMyYjNlOWI5MjhiZmU1MWJjZjRmOGRhNTQzY2M0YmQ5ZDQ3MjQiLCJ0eXAiOiJ
    KV1QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXpwIjoiZmFrZUBleGFtcGxlLmNvbSIsImVtYWlsIjoiZmF
    rZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE1OTk2MjE5MjgsImlhdCI6MTU5OTYxODMyOC
    wiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoxMTExMzMzNTU1Nzc3OTk5MDAwMDB9.c2lnbmF0
    dXJlCg
    RESPONSE;

    private const PROJECT_ID = "some-gcp-project";


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
        $fetcher    = new MetadataServerCredentials($fakeClient);

        $got = $fetcher->fetchAccessToken();

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertMatchesSnapshot($got);
    }

    public function testFetchesIdentityToken(): void {
        $responseBody = str_replace("\n", "", self::IDENTITY_TOKEN_RESPONSE);

        $responses = [
            new \GuzzleHttp\Psr7\Response(200, [], $responseBody),
        ];


        $fakeClient = $this->makeSnapshotClient($responses);
        $fetcher    = new MetadataServerCredentials($fakeClient);

        $got = $fetcher->fetchIdentityToken(self::AUDIENCE);

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertMatchesSnapshot($got);
    }

    public function testFetchesProjectID(): void {
        $responses = [
            new \GuzzleHttp\Psr7\Response(200, [], self::PROJECT_ID),
        ];


        $fakeClient = $this->makeSnapshotClient($responses);
        $fetcher    = new MetadataServerCredentials($fakeClient);

        $got = $fetcher->fetchProjectID();

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertSame(self::PROJECT_ID, $got);
    }

}
