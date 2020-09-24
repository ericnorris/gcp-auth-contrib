<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Fetcher;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\CachedCredentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;


/**
 * The AccessTokenFetcher class implements the official Google auth library's {@see
 * \Google\Auth\FetchAuthTokenInterface} for use in the PHP library. It may be passed as either a "credentials" or
 * "credentialsFetcher" option array key to a Google client.
 */
class AccessTokenFetcher implements
    \Google\Auth\FetchAuthTokenInterface,
    \Google\Auth\SignBlobInterface,
    \Google\Auth\ProjectIdProviderInterface {

    /**
     * @var Credentials
     */
    private $source;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * @var ?FetchAccessTokenResponse
     */
    private $lastReceivedToken;


    /**
     * @param Credentials $source
     * @param string[] $scopes
     */
    public function __construct(Credentials $source, array $scopes) {
        $this->source = $source;
        $this->scopes = $scopes;

        $this->lastReceivedToken = null;
    }

    /**
     * Fetches an *access token* from the underlying source credentials.
     *
     * @param callable $_ Unused.
     *
     * return array{access_token: string, expires_at: int}|null
     */
    public function fetchAuthToken(callable $_ = null) {
        $this->lastReceivedToken = $this->source->fetchAccessToken($this->scopes);

        return [
            "access_token" => $this->lastReceivedToken->getAccessToken(),
            "expires_at"   => $this->lastReceivedToken->getExpiresAt(),
        ];
    }

    /**
     * Not implemented. Use {@see CachedCredentials} instead, and pass in to this class as a $source argument.
     */
    public function getCacheKey() {
        throw new \RuntimeException("Not supported by this implementation.");
    }

    /**
     * Returns the service account email address of the underlying source credentials.
     *
     * @param callable $_ Unused.
     * @return string
     */
    public function getClientName(callable $_ = null) {
        return $this->source->fetchServiceAccountEmail();
    }

    /**
     * Returns an associative array with the last fetched access token and its expiration time.
     *
     * @return array{access_token: string, expires_at: int}|null
     */
    public function getLastReceivedToken() {
        if ($this->lastReceivedToken == null) {
            return null;
        }

        return [
            "access_token" => $this->lastReceivedToken->getAccessToken(),
            "expires_at"   => $this->lastReceivedToken->getExpiresAt(),
        ];
    }

    /**
     * Get the project ID from the underlying source credentials.
     *
     * @param callable $_ Unused.
     *
     * @return string|null
     */
    public function getProjectId(callable $_ = null) {
        if (!$this->source->supportsCapability(Credentials::CAN_FETCH_PROJECT_ID)) {
            return null;
        }

        return $this->source->fetchProjectID();
    }

    /**
     * Sign a blob using the underlying source credentials.
     *
     * @throws \BadMethodCallException If the underlying source does not support {@see Credentials::generateSignature}.
     *
     * @param string $stringToSign The string to sign.
     * @param bool $forceOpenssl Unused.
     *
     * @return string The signature for the given string.
     */
    public function signBlob($stringToSign, $forceOpenssl = false) {
        return $this->source->generateSignature($stringToSign)->getSignature();
    }

}
