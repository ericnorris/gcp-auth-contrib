<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheItemInterface;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Contracts\CredentialsWithProjectID;
use ericnorris\GCPAuthContrib\Contracts\ExpiresAt;
use ericnorris\GCPAuthContrib\Internal\Contracts\CacheAwareCredentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;
use ericnorris\GCPAuthContrib\Time;


/**
 * The CachedCredentials class fetches data from a credentials source and caches the results, taking care to handle
 * cache invalidation for results that have limited lifetimes.
 */
class CachedCredentials implements Credentials {

    /** NOTE: incrementing this version will bust the cache for all consumers of this library. */
    private const CACHE_VERSION = "v1";


    /** @var Credentials */
    private $source;

    /** @var CacheItemPoolInterface */
    private $cache;


    public function __construct(Credentials $source, CacheItemPoolInterface $cache) {
        $this->source = $source;
        $this->cache  = $cache;
    }

    /**
     * Fetches an access token from the underlying source credentials.
     *
     * @param string[] $scopes An array of scopes to request from the underlying source.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        return $this->memoize(
            $this->makeCacheKey(__FUNCTION__, ...$scopes),
            function() use ($scopes): FetchAccessTokenResponse {
                return $this->source->fetchAccessToken($scopes);
            },
        );
    }

    /**
     * Fetches an identity token from the underlying source credentials.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed ID token.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse {
        return $this->memoize(
            $this->makeCacheKey(__FUNCTION__, $audience),
            function() use ($audience): FetchIdentityTokenResponse {
                return $this->source->fetchIdentityToken($audience);
            },
        );
    }

    /**
     * Fetches the project ID from the underlying source credentials.
     *
     * @return string
     */
    public function fetchProjectID(): string {
        return $this->memoize(
            $this->makeCacheKey(__FUNCTION__),
            function(): string {
                return $this->source->fetchProjectID();
            },
        );
    }

    /**
     * Fetches the service account from the cached credentials.
     *
     * @return string
     */
    public function fetchServiceAccountEmail(): string {
        return $this->memoize(
            $this->makeCacheKey(__FUNCTION__),
            function(): string {
                return $this->source->fetchServiceAccountEmail();
            },
        );
    }

    /**
     * Generates a signature using the underlying source credentials.
     *
     * NOTE: the response is not cached.
     *
     * @param string $toSign The bytes to sign.
     *
     * @return GenerateSignatureResponse
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse {
        return $this->source->generateSignature($toSign);
    }

    /**
     * Returns true if the underlying source credentials supports the given capability.
     */
    public function supportsCapability(string $capability): bool {
        return $this->source->supportsCapability($capability);
    }

    /**
     * Executes the specified callable if and only if there is not a cache hit for the given key.
     *
     * @template T
     *
     * @param string $cacheKey The string to use for looking up previous results of the callable
     * @param callable():T $computation The callable to execute on cache miss
     *
     * @return T The result of the callable, potentially from the cache
     */
    private function memoize(string $cacheKey, callable $computation) {
        $cacheItem = $this->cache->getItem($cacheKey);

        if ($cacheItem->isHit()) {
            /** @var T */
            return $cacheItem->get();
        }

        $cacheItem->set($result = $computation());

        if ($result instanceof ExpiresAt) {
            $cacheItem->expiresAt($result->getExpiresAtDateTime());
        }

        $this->cache->save($cacheItem);

        return $result;
    }

    /**
     * Returns a string suitable for use as a cache key. Incorporates the class name of the underlying credential source
     * so that many copies of this class can coexist.
     *
     * @param string ...$args Any number of strings to also incorporate into the cache key.
     *
     * @return string
     */
    private function makeCacheKey(string ...$args): string {
        $cacheComponents = [
            self::CACHE_VERSION,
            \get_class($this->source),
            ...$args,
        ];

        if ($this->source instanceof CacheAwareCredentials) {
            $cacheComponents = array_merge(
                $cacheComponents,
                $this->source->extendCacheKey()
            );
        }

        return sha1(implode("-", $cacheComponents));
    }

}
