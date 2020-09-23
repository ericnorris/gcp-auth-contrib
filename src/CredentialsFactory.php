<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib;

use GuzzleHttp\ClientInterface;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\AuthorizedUserCredentials;
use ericnorris\GCPAuthContrib\Credentials\ImpersonatedCredentials;
use ericnorris\GCPAuthContrib\Credentials\MetadataServerCredentials;
use ericnorris\GCPAuthContrib\Credentials\ServiceAccountKey;


class CredentialsFactory {

    /** @var ClientInterface */
    private $httpClient;


    public function __construct(ClientInterface $httpClient) {
        $this->httpClient = $httpClient;
    }

    public function makeAuthorizedUserCredentials(array $credentials): AuthorizedUserCredentials {
        return new AuthorizedUserCredentials($this->httpClient, $credentials);
    }

    /**
     * @param string[] $delegates
     */
    public function makeImpersonatedCredentials(Credentials $source, string $target, array $delegates = []): ImpersonatedCredentials {
        return new ImpersonatedCredentials($this->httpClient, $source, $target, $delegates);
    }

    public function makeMetadataServerCredentials(): MetadataServerCredentials {
        return new MetadataServerCredentials($this->httpClient);
    }

    public function makeServiceAccountKey(array $credentials): ServiceAccountKey {
        return new ServiceAccountKey($this->httpClient, $credentials);
    }

}
