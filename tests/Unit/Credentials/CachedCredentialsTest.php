<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\CachedCredentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;


final class CachedCredentialsTest extends TestCase {

    private const EXAMPLE_SCOPES_01 = [
        "https://www.googleapis.com/auth/cloud-platform",
    ];

    private const EXAMPLE_SCOPES_02 = [
        "https://www.googleapis.com/auth/cloudkms",
        "https://www.googleapis.com/auth/compute.readonly",
    ];

    private const EXAMPLE_AUDIENCE_01 = "https://example.com";
    private const EXAMPLE_AUDIENCE_02 = "https://subdomain.example.com";


    public function testFetchesAccessToken(): void {
        $cache = new ArrayAdapter;

        $source  = new CredentialsImpl;
        $fetcher = new CachedCredentials($source, $cache);

        // cache miss and expired token
        $fetcher->fetchAccessToken(self::EXAMPLE_SCOPES_01);

        // token will not expire now
        $source->expires_in = 60;

        // cache miss
        $want = $fetcher->fetchAccessToken(self::EXAMPLE_SCOPES_01);

        // cache hit
        $got = $fetcher->fetchAccessToken(self::EXAMPLE_SCOPES_01);

        $this->assertSame(2, $source->timesCalled);
        $this->assertEquals($want, $got);

        // cache miss (different scopes)
        $want = $fetcher->fetchAccessToken(self::EXAMPLE_SCOPES_02);
        $got  = $fetcher->fetchAccessToken(self::EXAMPLE_SCOPES_02);

        $this->assertSame(3, $source->timesCalled);
        $this->assertEquals($want, $got);
    }

    public function testFetchesIdentityToken(): void {
        $cache = new ArrayAdapter;

        $source  = new CredentialsImpl;
        $fetcher = new CachedCredentials($source, $cache);

        // cache miss and expired token
        $fetcher->fetchIdentityToken(self::EXAMPLE_AUDIENCE_01);

        // token will not expire now
        $source->expires_in = 60;

        // cache miss
        $want = $fetcher->fetchIdentityToken(self::EXAMPLE_AUDIENCE_01);

        // cache hit
        $got = $fetcher->fetchIdentityToken(self::EXAMPLE_AUDIENCE_01);

        $this->assertSame(2, $source->timesCalled);
        $this->assertEquals($want, $got);

        // cache miss (different audience)
        $want = $fetcher->fetchIdentityToken(self::EXAMPLE_AUDIENCE_02);
        $got  = $fetcher->fetchIdentityToken(self::EXAMPLE_AUDIENCE_02);

        $this->assertSame(3, $source->timesCalled);
        $this->assertEquals($want, $got);
    }

    public function testFetchesProjectID(): void {
        $cache = new ArrayAdapter;

        $source  = new CredentialsImpl;
        $fetcher = new CachedCredentials($source, $cache);

        $want = $fetcher->fetchProjectID();
        $got  = $fetcher->fetchProjectID();

        $this->assertSame(1, $source->timesCalled);
        $this->assertSame($want, $got);
    }

    public function testGeneratesSignature(): void {
        $cache = new ArrayAdapter;

        $source  = new CredentialsImpl;
        $fetcher = new CachedCredentials($source, $cache);

        $dontWant = $fetcher->generateSignature("string");
        $got      = $fetcher->generateSignature("string");

        $this->assertSame(2, $source->timesCalled);
        $this->assertNotEquals($dontWant, $got);
    }

}

final class CredentialsImpl implements Credentials {

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
        $this->timesCalled++;

        $class    = new \ReflectionClass(FetchIdentityTokenResponse::class);
        $instance = $class->newInstanceWithoutConstructor();

        $idTokenProperty   = $class->getProperty("id_token");
        $expiresAtProperty = $class->getProperty("expires_at");

        $idTokenProperty->setAccessible(true);
        $idTokenProperty->setValue($instance, "id-token-{$this->timesCalled}-{$audience}");

        $expiresAtProperty->setAccessible(true);
        $expiresAtProperty->setValue($instance, time() + $this->expires_in);

        return $instance;
    }

    public function fetchProjectID(): string {
        $this->timesCalled++;

        return "a-project-id";
    }

    public function fetchServiceAccountEmail(): string {
        $this->timesCalled++;

        return "a-service-account@iam.a-project.gserviceaccount.com";
    }

    public function generateSignature(string $toSign): GenerateSignatureResponse {
        $this->timesCalled++;

        return new GenerateSignatureResponse("key-id-{$this->timesCalled}", "signature");
    }

    public function supportsCapability(string $capability): bool {
        return true;
    }

}