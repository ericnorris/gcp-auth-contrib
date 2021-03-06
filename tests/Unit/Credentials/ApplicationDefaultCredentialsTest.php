<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests\Unit\Credentials;

use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\ApplicationDefaultCredentials;
use ericnorris\GCPAuthContrib\Credentials\AuthorizedUserCredentials;
use ericnorris\GCPAuthContrib\Credentials\MetadataServerCredentials;
use ericnorris\GCPAuthContrib\Credentials\ServiceAccountKey;
use ericnorris\GCPAuthContrib\CredentialsFactory;


final class ApplicationDefaultCredentialsTest extends TestCase {

    private $vfs;

    private $mockCredentialsFactory;


    public function setUp(): void {
        $serviceAccountFileStub = "{\"type\": \"service_account\"}";
        $authUserFileStub       = "{\"type\": \"authorized_user\"}";

        $structure = [
            "service-account-file" => $serviceAccountFileStub,
            "oauth2-file"          => $authUserFileStub,

            "home-dir-with-service-account-file" => [
                ApplicationDefaultCredentials::WELL_KNOWN_FILE_PATH => $serviceAccountFileStub,
            ],

            "home-dir-with-oauth2-file" => [
                ApplicationDefaultCredentials::WELL_KNOWN_FILE_PATH => $authUserFileStub,
            ],

            "home-dir-with-nothing" => [],
        ];

        $this->vfs = vfsStream::setup('root', null, $structure);

        $this->mockCredentialsFactory = $this->createMock(CredentialsFactory::class);
    }

    /**
     * @dataProvider envVarPathProvider
     */
    public function testLazyLoad(array $envVars, string $expectedClass): void {
        foreach ($envVars as $name => $path) {
            $vfsPath = $this->vfs->getChild($path)->url();

            putenv("$name=$vfsPath");
        }

        $adc = new ApplicationDefaultCredentials($this->mockCredentialsFactory);

        $this->assertEmpty($adc->getCredentialsClass());

        $adc->fetchAccessToken();

        $credentialsClass = $adc->getCredentialsClass();

        $this->assertTrue(
            \is_a($credentialsClass, $expectedClass, $allow_string = true),
            "Expected instance of $expectedClass, got $credentialsClass",
        );

        foreach ($envVars as $name => $_) {
            putenv("$name=");
        }
    }

    public function testPassthrough(): void {
        $mockCredentials = $this->createMock(MetadataServerCredentials::class);

        $this->mockCredentialsFactory
            ->method("makeMetadataServerCredentials")
            ->willReturn($mockCredentials);

        $adc = new ApplicationDefaultCredentials($this->mockCredentialsFactory);

        $mockCredentials
            ->expects($this->once())
            ->method("fetchAccessToken");

        $adc->fetchAccessToken();

        $mockCredentials
            ->expects($this->once())
            ->method("fetchIdentityToken");

        $adc->fetchIdentityToken("https://example.com");

        $mockCredentials
            ->expects($this->once())
            ->method("fetchProjectID");

        $adc->fetchProjectID();

        $mockCredentials
            ->expects($this->once())
            ->method("fetchServiceAccountEmail");

        $adc->fetchServiceAccountEmail();

        $mockCredentials
            ->expects($this->once())
            ->method("generateSignature");

        $adc->generateSignature("toSign");

        $mockCredentials
            ->expects($this->once())
            ->method("supportsCapability");

        $adc->supportsCapability(Credentials::CAN_FETCH_PROJECT_ID);
    }

    public function envVarPathProvider(): array {
        $serviceAccountAtWellKnownEnvVarSetup = [
            ApplicationDefaultCredentials::WELL_KNOWN_ENV_VAR => "service-account-file",
        ];

        $oauth2FileAtWellKnownEnvVarSetup = [
            ApplicationDefaultCredentials::WELL_KNOWN_ENV_VAR => "oauth2-file",
        ];

        $serviceAccountAtWellKnownFilePathSetup = [
            "HOME" => "home-dir-with-service-account-file",
        ];

        $oauth2FileAtWellKnownFilePathSetup = [
            "HOME" => "home-dir-with-oauth2-file",
        ];

        $metadataServerSetup = [
            "HOME" => "home-dir-with-nothing",
        ];

        return [
            [$serviceAccountAtWellKnownEnvVarSetup, ServiceAccountKey::class],
            [$serviceAccountAtWellKnownFilePathSetup, ServiceAccountKey::class],
            [$oauth2FileAtWellKnownEnvVarSetup, AuthorizedUserCredentials::class],
            [$oauth2FileAtWellKnownFilePathSetup, AuthorizedUserCredentials::class],
            [$metadataServerSetup, MetadataServerCredentials::class],
        ];
    }
}
