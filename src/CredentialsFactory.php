<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib;

use GuzzleHttp\ClientInterface;
use Psr\Cache\CacheItemPoolInterface;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\ApplicationDefaultCredentials;
use ericnorris\GCPAuthContrib\Credentials\AuthorizedUserCredentials;
use ericnorris\GCPAuthContrib\Credentials\CachedCredentials;
use ericnorris\GCPAuthContrib\Credentials\CredentialsWithImpersonationFallback;
use ericnorris\GCPAuthContrib\Credentials\ImpersonatedCredentials;
use ericnorris\GCPAuthContrib\Credentials\MetadataServerCredentials;
use ericnorris\GCPAuthContrib\Credentials\ServiceAccountKey;


/**
 * The CredentialsFactory class provides an unopinionated way of creating various {@see Credentials} instances.
 */
class CredentialsFactory {

    /** @var ClientInterface */
    private $httpClient;

    /** @var CacheItemPoolInterface */
    private $cache;


    public function __construct(ClientInterface $httpClient, CacheItemPoolInterface $cache) {
        $this->httpClient = $httpClient;
        $this->cache      = $cache;
    }

    /**
     * Returns an {@see ApplicationDefaultCredentials} instance.
     */
    public function makeApplicationDefaultCredentials(): ApplicationDefaultCredentials {
        return new ApplicationDefaultCredentials($this);
    }

    /**
     * Returns an {@see AuthorizedUserCredentials} instance.
     */
    public function makeAuthorizedUserCredentials(array $credentials): AuthorizedUserCredentials {
        return new AuthorizedUserCredentials($this->httpClient, $credentials);
    }

    /**
     * Returns a {@see CachedCredentials} instance.
     */
    public function makeCachedCredentials(Credentials $source): CachedCredentials {
        return new CachedCredentials($source, $this->cache);
    }

    public function makeCredentialsWithImpersonationFallback(Credentials $source, ?string $fallbackAccount = null): CredentialsWithImpersonationFallback {
        return new CredentialsWithImpersonationFallback($source, $this, $fallbackAccount);
    }

    /**
     * Returns an {@see ImpersonatedCredentials} instance.
     *
     * @param Credentials $source
     * @param string $target
     * @param string[] $delegates
     */
    public function makeImpersonatedCredentials(Credentials $source, string $target, array $delegates = []): ImpersonatedCredentials {
        return new ImpersonatedCredentials($this->httpClient, $source, $target, $delegates);
    }

    /**
     * Returns an {@see MetadataServerCredentials} instance.
     */
    public function makeMetadataServerCredentials(): MetadataServerCredentials {
        return new MetadataServerCredentials($this->httpClient);
    }

    /**
     * Returns an {@see ServiceAccountKey} instance.
     */
    public function makeServiceAccountKey(array $credentials): ServiceAccountKey {
        return new ServiceAccountKey($this->httpClient, $credentials);
    }

}
