<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Internal\Contracts;

/**
 * Classes implementing the CacheAwareCredentials interface can provide additional information to a cache in order to
 * ensure that tokens from the class are cached properly
 */
interface CacheAwareCredentials {

    /**
     * Returns additional strings that can be incorporated into a cache key for this class.
     *
     * @return string[]
     */
    public function extendCacheKey(): array;

}
