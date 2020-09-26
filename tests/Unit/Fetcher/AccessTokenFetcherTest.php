<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use PHPUnit\Framework\TestCase;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Fetcher\AccessTokenFetcher;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;


final class AccessTokenFetcherTest extends TestCase {

    private const EXAMPLE_SCOPES_01 = [
        "https://www.googleapis.com/auth/cloud-platform",
    ];

    private const TOKEN_STRING = "token-string";
    private const EXPIRES_AT   = 1234;


    public function setUp(): void {
        $this->mockCredentials = $this->createMock(Credentials::class);

        $this->sut = new AccessTokenFetcher($this->mockCredentials, self::EXAMPLE_SCOPES_01);
    }

    public function testFetchesAuthToken(): void {
        $this->assertNull($this->sut->getLastReceivedToken());

        $accessTokenResponse = new FetchAccessTokenResponse(self::TOKEN_STRING, self::EXPIRES_AT, "", "Bearer");

        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchAccessToken")
            ->with(self::EXAMPLE_SCOPES_01)
            ->willReturn($accessTokenResponse);

        $want = [
            "access_token" => self::TOKEN_STRING,
            "expires_at"   => self::EXPIRES_AT,
        ];

        $got = $this->sut->fetchAuthToken();

        $this->assertEquals($want, $got);

        $got = $this->sut->getLastReceivedToken();

        $this->assertEquals($want, $got);
    }

    public function testGetsClientName(): void {
        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchServiceAccountEmail")
            ->willReturn($want = "some-email");

        $got = $this->sut->getClientName();

        $this->assertSame($want, $got);
    }

    public function testGetsProjectID(): void {
        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    case Credentials::CAN_FETCH_PROJECT_ID:
                        return true;

                    default:
                        return false;
                }
            }));

        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchProjectID")
            ->willReturn($want = "some-project");

        $got = $this->sut->getProjectId();

        $this->assertSame($want, $got);
    }

    public function testReturnsNullForGetProjectID(): void {
        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    default:
                        return false;
                }
            }));

        $this->mockCredentials
            ->expects($this->never())
            ->method("fetchProjectID")
            ->willReturn("shouldn't be called");

        $got = $this->sut->getProjectId();

        $this->assertNull($got);
    }

    public function testSignsBlob(): void {
        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    case Credentials::CAN_GENERATE_SIGNATURE:
                        return true;

                    default:
                        return false;
                }
            }));

        $this->mockCredentials
            ->expects($this->once())
            ->method("generateSignature");

        $this->sut->signBlob("toSign");
    }

    public function testThrowsExceptionForSignBlob(): void {
        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    default:
                        return false;
                }
            }));

        $this->mockCredentials
            ->expects($this->never())
            ->method("generateSignature");

        $this->expectException(\BadMethodCallException::class);

        $this->sut->signBlob("toSign");
    }

}
