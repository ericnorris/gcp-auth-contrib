<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Request;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;
use ericnorris\GCPAuthContrib\Time;


/**
 * The MetadataServerCredentials class fetches various information from the {@link
 * https://cloud.google.com/compute/docs/storing-retrieving-metadata metadata server}.
 *
 */
class MetadataServerCredentials implements Credentials {

    const METADATA_ENDPOINT = "http://169.254.169.254/computeMetadata/v1/";

    const ACCESS_TOKEN_URI    = "instance/service-accounts/default/token";
    const ID_TOKEN_URI        = "instance/service-accounts/default/identity";
    const SERVICE_ACCOUNT_URI = "instance/service-accounts/default/email";

    const PROJECT_URI = "project/project-id";


    /** @var ClientInterface */
    private $httpClient;


    public function __construct(ClientInterface $httpClient) {
        $this->httpClient = $httpClient;
    }

    /**
     * Fetches an access token from the {@link https://cloud.google.com/compute/docs/storing-retrieving-metadata
     * metadata server}.
     *
     * @param string[] $scopes An array of scopes to request from the metadata server. Only supported on App Engine,
     *        Cloud Functions, and Cloud Run.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        $params = [];

        if (!empty($scopes)) {
            $params["scopes"] = implode(",", $scopes);
        }

        $responseBody = $this->sendMetadataRequest(self::ACCESS_TOKEN_URI, \http_build_query($params));
        $responseData = (array)\json_decode($responseBody, true, 16, JSON_THROW_ON_ERROR);

        if (!isset($responseData["expires_in"])) {
            throw new \DomainException("Response is missing 'expires_in' field");
        }

        return new FetchAccessTokenResponse(
            (string)$responseData["access_token"],
            Time::calculateExpiresAt((int)$responseData["expires_in"])->getTimestamp(),
            (string)$responseData["scope"],
            "Bearer",
        );
    }

    /**
     * Fetches an identity token from the
     * {@link https://cloud.google.com/compute/docs/instances/verifying-instance-identity#request_signature
     * metadata server}.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed ID token.
     * @param string $format The "format" parameter for the ID token.
     * @param bool $licenses True if the ID token should contain license codes associated with the instance this is
     *        running on.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience, string $format = "", bool $licenses = false): FetchIdentityTokenResponse {
        $params = [
            "audience" => $audience,
        ];

        if (!empty($format)) {
            $params["format"] = $format;
        }

        if ($licenses) {
            $params["licenses"] = $licenses;
        }

        $responseBody = $this->sendMetadataRequest(self::ID_TOKEN_URI, \http_build_query($params));

        return new FetchIdentityTokenResponse($responseBody);
    }

    /**
     * Fetches the project ID from the metadata server.
     *
     * @return string
     */
    public function fetchProjectID(): string {
        return $this->sendMetadataRequest(self::PROJECT_URI);
    }

    /**
     * Fetches the service account email from the metadata server.
     *
     * @return string
     */
    public function fetchServiceAccountEmail(): string {
        return $this->sendMetadataRequest(self::SERVICE_ACCOUNT_URI);
    }

    /**
     * Not supported.
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse {
        throw new \BadMethodCallException(__CLASS__ . " does not support " . __FUNCTION__);
    }

    /**
     * Returns true if this class supports the given capability.
     */
    public function supportsCapability(string $capability): bool {
        switch ($capability) {
            case Credentials::CAN_FETCH_PROJECT_ID:
                return true;

            case Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL:
                return true;

            case Credentials::CAN_GENERATE_SIGNATURE:
                return false;
        }
    }

    private function sendMetadataRequest(string $uri, string $params = ""): string {
        $response = $this->httpClient->send(new Request(
            "GET",
            self::METADATA_ENDPOINT . $uri,
            [
                "Metadata-Flavor" => "Google",
            ],
            $params,
        ));

        return (string)$response->getBody();
    }

}
