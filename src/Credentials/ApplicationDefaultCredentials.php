<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Contracts\CredentialsWithProjectID;
use ericnorris\GCPAuthContrib\CredentialsFactory;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;


/**
 * The ApplicationDefaultCredentials class follows the
 * {@link https://cloud.google.com/docs/authentication/production#automatically ApplicationDefaultCredentials} pattern.
 *
 * It defers credential loading until first use, in order to avoid causing spurious IO.
 */
class ApplicationDefaultCredentials implements Credentials {

    const WELL_KNOWN_ENV_VAR   = "GOOGLE_APPLICATION_CREDENTIALS";
    const WELL_KNOWN_FILE_PATH = ".config/gcloud/application_default_credentials.json";


    /** @var CredentialsFactory */
    private $credentialsFactory;

    /** @var ?Credentials */
    private $lazyCredentials;


    public function __construct(CredentialsFactory $factory) {
        $this->credentialsFactory = $factory;
        $this->lazyCredentials    = null;
    }

    /**
     * @return class-string|null
     */
    public function getCredentialsClass(): ?string {
        return $this->lazyCredentials ? \get_class($this->lazyCredentials) : null;
    }

    /**
     * Fetches an access token using the {@link https://cloud.google.com/docs/authentication/production#automatically
     * ApplicationDefaultCredentials} pattern.
     *
     * @param string[] $scopes An array of scopes to request from default credentials.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        return $this->getLazyCredentials()->fetchAccessToken($scopes);
    }

    /**
     * Fetches an ID token using the {@link https://cloud.google.com/docs/authentication/production#automatically
     * ApplicationDefaultCredentials} pattern.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed ID token.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse {
        return $this->getLazyCredentials()->fetchIdentityToken($audience);
    }

    /**
     * Fetches the project ID from the default credentials.
     *
     * @return string
     */
    public function fetchProjectID(): string {
        return $this->getLazyCredentials()->fetchProjectID();
    }

    /**
     * Generates a signature using the default credentials.
     *
     * @param string $toSign The bytes to sign.
     *
     * @return GenerateSignatureResponse
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse {
        return $this->getLazyCredentials()->generateSignature($toSign);
    }

    /**
     * Returns true if the default credentials supports the given capability.
     */
    public function supportsCapability(string $capability): bool {
        return $this->getLazyCredentials()->supportsCapability($capability);
    }

    private function getLazyCredentials(): Credentials {
        if ($this->lazyCredentials !== null) {
            return $this->lazyCredentials;
        }

        $envVarCredentials = $this->readEnvironmentVariableFile();

        if (ServiceAccountKey::isServiceAccountKey($envVarCredentials)) {
            return $this->lazyCredentials = $this->credentialsFactory->makeServiceAccountKey($envVarCredentials);
        }

        if (AuthorizedUserCredentials::isAuthorizedUserCredentials($envVarCredentials)) {
            return $this->lazyCredentials = $this->credentialsFactory->makeAuthorizedUserCredentials(
                $envVarCredentials
            );
        }

        $wellKnownFileCredentials = $this->readWellKnownFile();

        if (ServiceAccountKey::isServiceAccountKey($wellKnownFileCredentials)) {
            return $this->lazyCredentials = $this->credentialsFactory->makeServiceAccountKey($wellKnownFileCredentials);
        }

        if (AuthorizedUserCredentials::isAuthorizedUserCredentials($wellKnownFileCredentials)) {
            return $this->lazyCredentials = $this->credentialsFactory->makeAuthorizedUserCredentials(
                $wellKnownFileCredentials
            );
        }

        return $this->lazyCredentials = $this->credentialsFactory->makeMetadataServerCredentials();
    }

    private function readEnvironmentVariableFile(): array {
        $path = (string)getenv(self::WELL_KNOWN_ENV_VAR);

        if (empty($path)) {
            return [];
        }

        $jsonString = @\file_get_contents($path) ?: "";

        return (array)json_decode($jsonString, true);
    }

    private function readWellKnownFile(): array {
        $parentDir = (string)getenv("HOME");
        $path      = $parentDir . DIRECTORY_SEPARATOR . self::WELL_KNOWN_FILE_PATH;

        $jsonString = @\file_get_contents($path) ?: "";

        return (array)json_decode($jsonString, true);
    }

}
