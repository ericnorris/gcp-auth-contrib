<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Symfony\Component\Cache\Adapter\ChainAdapter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Google\Auth\FetchAuthTokenInterface;

use ericnorris\GCPAuthContrib\Credentials\CachedCredentials;
use ericnorris\GCPAuthContrib\Fetcher\AccessTokenFetcher;
use ericnorris\GCPAuthContrib\CredentialsFactory;


/**
 * The OpinionatedDefaults class provides a near decision-less way of constructing {@see Credentials} or
 * {@see FetchAuthTokenInterface} instances.
 *
 * You can pass instances of the {@see FetchAuthTokenInterface} instances created from this class as either a
 * "credentials" or "credentialsFetcher" option array key to the various Google Cloud PHP library clients.
 *
 * These defaults follow Google's best practices of using the {@link
 * https://cloud.google.com/docs/authentication/production ApplicationDefaultCredentials} pattern and strive to avoid
 * IO by caching credential requests where possible.
 */
class OpinionatedDefaults {

    private const CACHE_NAMESPACE = "gcp-auth-contrib";

    private const DEFAULT_SCOPES = [
        "https://www.googleapis.com/auth/cloud-platform",
    ];


    /** @var CredentialsFactory */
    private $credentialsFactory;


    /**
     * Constructs an instance of OpinionatedDefaults.
     *
     * Only needed if you want to tweak the {@see CredentialsFactory} parameters. If not, use the {@see ::get()} method
     * below.
     */
    public function __construct(CredentialsFactory $credentialsFactory) {
        $this->credentialsFactory = $credentialsFactory;
    }

    /**
     * Gets an instance of the OpinionatedDefaults class with... opinionated defaults for the {@see CredentialsFactory}
     * that powers it.
     *
     * The current defaults:
     *   - use a plain Guzzle client for HTTP requests
     *   - use a chained cache adapter, where tokens are cached to disk but kept in memory for the duration of the
     *     script.
     */
    public static function get(): self {
        return new self(
            new CredentialsFactory(
                new Client,
                new ChainAdapter([new ArrayAdapter, new FilesystemAdapter(self::CACHE_NAMESPACE)]),
            ),
        );
    }

    /**
     * Makes a cached instance of {@see ApplicationDefaultCredentials}, with a fallback to using {@see
     * ImpersonatedCredentials} for times when the default credentials do not support the {@see
     * Credentials::fetchIdentityToken} or {@see Credentials::generateSignature} capabilities.
     *
     * This is often the case with the default credentials for code that is running on Google Compute Engine instances
     * or in their serverless offerings - the "metadata server" (represented by {@see MetadataServerCredentials}) cannot
     * generate signatures, and in some cases (e.g. GKE's Workload Identity) cannot fetch identity tokens.
     *
     * It's unlikely you will need this; you will want the {@see FetchAuthTokenInterface} from the {@see
     * ::makeCredentialsFetcher()} method below instead.
     */
    public function makeCredentials(): CachedCredentials {
        return $this->credentialsFactory->makeCachedCredentials(
            $this->credentialsFactory->makeCredentialsWithImpersonationFallback(
                $this->credentialsFactory->makeCachedCredentials(
                    $this->credentialsFactory->makeApplicationDefaultCredentials(),
                ),
            ),
        );
    }

    /**
     * Makes a {@see FetchAuthTokenInterface} instance using the Application Default Credentials pattern with the
     * opinions from {@see ::makeCredentials()}.
     *
     * Can be used as a "credentials" or "credentialsFetcher" option array key for the Google Cloud PHP library clients.
     *
     * @param ?string[] $scopes The desired scopes for the access tokens this will fetch. Uses sane defaults.
     *
     * @return FetchAuthTokenInterface
     */
    public function makeCredentialsFetcher(array $scopes = null): FetchAuthTokenInterface {
        return new AccessTokenFetcher($this->makeCredentials(), $scopes ?? self::DEFAULT_SCOPES);
    }

    /**
     * Makes a cached instance of {@see ImpersonatedCredentials} that uses the opinionated defaults from {@see
     * ::makeCredentials} as the source credentials. Use this to impersonate another service account.
     *
     * It's unlikely you will need this; you will want the {@see FetchAuthTokenInterface} from the {@see
     * ::makeImpersonatedCredentialsFetcher()} method below instead.
     *
     * @param string $target The email of the service account to impersonate.
     */
    public function makeImpersonatedCredentials(string $target): CachedCredentials {
        $impersonatedCredentials = $this->credentialsFactory->makeImpersonatedCredentials(
            $source = $this->makeCredentials(),
            $target,
            $delegates = [],
        );

        return $this->credentialsFactory->makeCachedCredentials($impersonatedCredentials);
    }

    /**
     * Makes a {@see FetchAuthTokenInterface} instance that can impersonate another service account.
     *
     * Can be used as a "credentials" or "credentialsFetcher" option array key for the Google Cloud PHP library clients.
     *
     * @param string $target The email of the service account to impersonate.
     * @param ?string[] $scopes The desired scopes for the access tokens this will fetch. Uses sane defaults.
     */
    public function makeImpersonatedCredentialsFetcher(string $target, array $scopes = null): FetchAuthTokenInterface {
        return new AccessTokenFetcher(
            $this->makeImpersonatedCredentials($target),
            $scopes ?? self::DEFAULT_SCOPES,
        );
    }

}
