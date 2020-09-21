<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Internal\Credentials;

use PHPUnit\Framework\TestCase;
use Spatie\Snapshots\MatchesSnapshots;

use ericnorris\GCPAuthContrib\Internal\Credentials\OAuth2Credentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Tests\MatchesRequestSnapshots;
use ericnorris\GCPAuthContrib\Time;


final class OAuth2CredentialsTest extends TestCase {
    use MatchesRequestSnapshots;

    private const NOW = 1596153600;

    private const ACCESS_TOKEN_RESPONSE = <<<'RESPONSE'
    {
        "access_token": "1/8xbJqaOZXSUZbHLl5EOtu1pxz3fmmetKx9W8CV4t79M",
        "expires_in"  : 3600,
        "scope"       : "https://www.googleapis.com/auth/cloud-platform",
        "token_type"  : "Bearer"
    }
    RESPONSE;

    private const AUDIENCE = "https://example.com";

    private const IDENTITY_TOKEN_RESPONSE = <<<'RESPONSE'
    {
        "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNmMzMyYjNlOWI5MjhiZmU1MWJjZjRmOGRhNTQzY2M0YmQ5ZDQ3MjQiLCJ0eXAiOiJ
        KV1QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXpwIjoiZmFrZUBleGFtcGxlLmNvbSIsImVtYWlsIjoiZmF
        rZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE1OTk2MjE5MjgsImlhdCI6MTU5OTYxODMyOC
        wiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoxMTExMzMzNTU1Nzc3OTk5MDAwMDB9.c2lnbmF0
        dXJlCg"
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
        $fetcher    = new OAuth2CredentialsImpl($fakeClient);

        $got = $fetcher->fetchAccessToken(["https://www.googleapis.com/auth/cloud-platform"]);

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertMatchesSnapshot($got);
    }

    public function testFetchesIdentityToken(): void {
        $responseBody = str_replace(["\n", " "], "", self::IDENTITY_TOKEN_RESPONSE);

        $responses = [
            new \GuzzleHttp\Psr7\Response(200, [], $responseBody),
        ];


        $fakeClient = $this->makeSnapshotClient($responses);
        $fetcher    = new OAuth2CredentialsImpl($fakeClient);

        $got = $fetcher->fetchIdentityToken(self::AUDIENCE);

        $this->assertRequestHistoryMatchesSnapshot();
        $this->assertMatchesSnapshot($got);
    }

}

final class OAuth2CredentialsImpl extends OAuth2Credentials {

    public function getOAuth2GrantType(): string {
        return "a-grant-type";
    }

    public function assertClaims(array $claims): array {
        return $claims + ["assertion-field" => "assertion"];
    }

}
