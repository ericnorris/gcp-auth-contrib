<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use PHPUnit\Framework\TestCase;
use Spatie\Snapshots\MatchesSnapshots;

use ericnorris\GCPAuthContrib\Credentials\AuthorizedUserCredentials;
use ericnorris\GCPAuthContrib\Time;


final class AuthorizedUserCredentialsTest extends TestCase {
    use MatchesSnapshots;

    const VALID_USER_CREDENTIALS = [
        "client_id"     => "a-client-id.apps.googleusercontent.com",
        "client_secret" => "a-client-secret",
        "refresh_token" => "a-refresh-token",
        "type"          => "authorized_user"
    ];

    /**
     * @dataProvider oauth2CredentialsProvider
     */
    public function testDetectsOAuth2Credentials(array $credentials, bool $valid): void {
        if (!$valid) {
            $this->expectException(\InvalidArgumentException::class);
        }

        $fetcher = new AuthorizedUserCredentials(new \GuzzleHttp\Client, $credentials, []);

        $this->assertNotNull($fetcher);
    }

    public function testAssertClaims(): void {
        $fetcher = new AuthorizedUserCredentials(new \GuzzleHttp\Client, self::VALID_USER_CREDENTIALS);

        $assertClaimsMethod = new \ReflectionMethod(AuthorizedUserCredentials::class, "assertClaims");
        $assertClaimsMethod->setAccessible(true);

        $got = $assertClaimsMethod->invoke($fetcher, ["claim-1" => "value"]);

        $this->assertMatchesSnapshot($got);
    }

    public function oauth2CredentialsProvider(): array {
        $wrongType = [
            "type" => "not_authorized_user",
        ] + self::VALID_USER_CREDENTIALS;

        $missingClientId = [
            "client_id" => null,
        ] + self::VALID_USER_CREDENTIALS;

        $missingClientSecret = [
            "client_secret" => null,
        ] + self::VALID_USER_CREDENTIALS;

        $missingRefreshToken = [
            "refresh_token" => null,
        ] + self::VALID_USER_CREDENTIALS;

        return [
            [$wrongType, false],
            [$missingClientId, false],
            [$missingClientSecret, false],
            [$missingRefreshToken, false],
            [self::VALID_USER_CREDENTIALS, true]
        ];
    }

    protected function getSnapshotDirectory(): string {
        return __DIR__ . "/../../../snapshots";
    }

}
