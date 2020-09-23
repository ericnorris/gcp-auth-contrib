<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Contracts;

use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;


/**
 * Classes implementing the Credentials interface can fetch a short-lived access token or Google-signed identity token
 * for use with Google Cloud Platform (GCP) products.
 */
interface Credentials {

    const CAN_FETCH_PROJECT_ID            = "fetchProjectID";
    const CAN_FETCH_SERVICE_ACCOUNT_EMAIL = "fetchServiceAccountEmail";
    const CAN_GENERATE_SIGNATURE          = "generateSignature";


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

    /**
     * Fetches the project ID associated with these credentials.
     *
     * @return string
     */
    public function fetchProjectID(): string;

    /**
     * Fetches the service account email for these credentials.
     *
     * @return string
     */
    public function fetchServiceAccountEmail(): string;

    /**
     * Generates a signature for the given byte string.
     *
     * @param string $toSign The bytes to sign.
     *
     * @return GenerateSignatureResponse
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse;

    /**
     * Returns true if the given ::CAN_* enum is supported by this implementation.
     *
     * @param self::CAN_FETCH_PROJECT_ID|self::CAN_FETCH_SERVICE_ACCOUNT_EMAIL|self::CAN_GENERATE_SIGNATURE $capability
     *
     * @return bool
     */
    public function supportsCapability(string $capability): bool;

}
