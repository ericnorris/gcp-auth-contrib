<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Contracts;

use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;


/**
 * Classes implementing the Credentials interface can fetch a short-lived access token or Google-signed identity token
 * for use with Google Cloud Platform (GCP) products.
 */
interface Credentials {

    /**
     * Returns a {@see FetchAccessTokenResponse} from the underlying source.
     *
     * @param string[] $scopes An array of scopes to request with the access token; though this may not be supported by
     *        all credentials.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse;

    /**
     * Returns a {@see FetchIdentityTokenResponse} from the underlying source.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed identity token.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse;

}
