<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use Fig\Http\Message\StatusCodeInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\CredentialsWithImpersonationFallback;
use ericnorris\GCPAuthContrib\Credentials\ImpersonatedCredentials;
use ericnorris\GCPAuthContrib\CredentialsFactory;


final class CredentialsWithImpersonationFallbackTest extends TestCase {

    private const EXAMPLE_AUDIENCE_01 = "https://example.com";

    public function setUp(): void {
        $this->mockCredentials = $this->createMock(Credentials::class);
        $this->mockFactory     = $this->createMock(CredentialsFactory::class);
        $this->mockFallback    = $this->createMock(ImpersonatedCredentials::class);

        $this->mockFactory
            ->method("makeImpersonatedCredentials")
            ->willReturn($this->mockFallback);

        $this->sut = new CredentialsWithImpersonationFallback($this->mockCredentials, $this->mockFactory);

        $this->sutWithFallbackAccount = new CredentialsWithImpersonationFallback(
            $this->mockCredentials,
            $this->mockFactory,
            "fallback-account",
        );
    }

    public function testFetchesAccessToken(): void {
        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchAccessToken");

        $this->sut->fetchAccessToken();
    }

    public function testFetchesIdentityToken(): void {
        $dummyRequest = new Request("GET", "some-endpoint-that-404s");
        $badResponse  = new Response(StatusCodeInterface::STATUS_NOT_FOUND);
        $exception    = new ClientException("test 404", $dummyRequest, $badResponse);

        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    case Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL:
                        return true;

                    default:
                        return false;
                }
            }));

        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchServiceAccountEmail");

        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchIdentityToken")
            ->willThrowException($exception);

        $this->mockFallback
            ->expects($this->once())
            ->method("fetchIdentityToken")
            ->with(self::EXAMPLE_AUDIENCE_01);

        $this->sut->fetchIdentityToken(self::EXAMPLE_AUDIENCE_01);
    }

    public function testFetchesIdentityTokenThrowsException(): void {
        $dummyRequest = new Request("GET", "some-endpoint-that-500s");
        $badResponse  = new Response(StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR);
        $exception    = new ClientException("test 500", $dummyRequest, $badResponse);

        $this->mockCredentials
            ->expects($this->once())
            ->method("fetchIdentityToken")
            ->willThrowException($exception);

        $this->expectException(ClientException::class);

        $this->sut->fetchIdentityToken(self::EXAMPLE_AUDIENCE_01);
    }

    public function testGeneratesSignature(): void {
        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    case Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL:
                        return true;

                    default:
                        return false;
                }
            }));

        $this->mockFallback
            ->expects($this->once())
            ->method("generateSignature");

        $this->sut->generateSignature("toSign");
    }

    public function testGeneratesSignatureException(): void {
        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) {
                switch ($capability) {
                    default:
                        return false;
                }
            }));

        $this->expectException(\BadMethodCallException::class);

        $this->sut->generateSignature("toSign");
    }

    public function testGeneratesSignaturePassthrough(): void {
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

        $this->mockFallback
            ->expects($this->never())
            ->method("generateSignature");

        $this->sut->generateSignature("toSign");
    }

    public function testSupportsCapability(): void {
        $supported = [];

        $this->mockCredentials
            ->expects($this->any())
            ->method("supportsCapability")
            ->will($this->returnCallback(function(string $capability) use (&$supported) {
                return \in_array($capability, $supported);
            }));

        $supported = [
            Credentials::CAN_FETCH_PROJECT_ID,
            Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL,
            Credentials::CAN_GENERATE_SIGNATURE,
        ];

        $this->assertTrue($this->sut->supportsCapability(Credentials::CAN_FETCH_PROJECT_ID));
        $this->assertTrue($this->sut->supportsCapability(Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL));
        $this->assertTrue($this->sut->supportsCapability(Credentials::CAN_GENERATE_SIGNATURE));

        $supported = [
            Credentials::CAN_FETCH_PROJECT_ID,
            Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL,
        ];

        $this->assertTrue($this->sut->supportsCapability(Credentials::CAN_GENERATE_SIGNATURE));

        $supported = [
            Credentials::CAN_FETCH_PROJECT_ID,
        ];

        $this->assertFalse($this->sut->supportsCapability(Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL));
        $this->assertFalse($this->sut->supportsCapability(Credentials::CAN_GENERATE_SIGNATURE));

        $this->assertTrue($this->sutWithFallbackAccount->supportsCapability(Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL));
        $this->assertTrue($this->sutWithFallbackAccount->supportsCapability(Credentials::CAN_GENERATE_SIGNATURE));
    }

}
