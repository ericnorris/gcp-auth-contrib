<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Request;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Internal\Contracts\CacheAwareCredentials;
use ericnorris\GCPAuthContrib\Internal\Contracts\ParsesRFC3339Timestamps;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;


/**
 * The ImpersonatedCredentials class uses the {@link https://cloud.google.com/iam/docs/reference/credentials/rest
 * IAM Credentials API} in order to impersonate a target service account following the {@link
 * https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials short lived credentials} guide.
 */
class ImpersonatedCredentials implements Credentials, CacheAwareCredentials {
    use ParsesRFC3339Timestamps;


    const SERVICE_ENDPOINT = "https://iamcredentials.googleapis.com/v1/";

    const ACCESS_TOKEN_URI   = "projects/-/serviceAccounts/%s:generateAccessToken";
    const IDENTITY_TOKEN_URI = "projects/-/serviceAccounts/%s:generateIdToken";
    const SIGN_BLOB_URI      = "projects/-/serviceAccounts/%s:signBlob";

    private const IAM_CREDENTIALS_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"];


    /** @var ClientInterface */
    private $httpClient;

    /** @var Credentials */
    private $source;

    /** @var string */
    private $target;

    /** @var string[] */
    private $delegates;


    /**
     * @param ClientInterface $client
     * @param Credentials $source
     * @param string $target
     * @param string[] $delegates
     */
    public function __construct(ClientInterface $client, Credentials $source, string $target, array $delegates = []) {
        $this->httpClient = $client;
        $this->source     = $source;
        $this->target     = $target;
        $this->delegates  = $delegates;
    }

    /**
     * Fetches an access token using the IAM Credentials REST API
     * {@link https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
     * generateAccessToken} endpoint.
     *
     * @param string[] $scopes An array of scopes to request for the target service account's access token, must not be
     *        empty.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        if (empty($scopes)) {
            throw new \InvalidArgumentException("\$scopes array cannot be empty");
        }

        $params = [
            "lifetime" => "3600s",
            "scope"    => $scopes,
        ];

        if (!empty($this->delegates)) {
            $params["delegates"] = $this->delegates;
        }

        $responseData = $this->sendIAMCredentialsRequest(
            \sprintf(self::ACCESS_TOKEN_URI, $this->target),
            $params,
        );

        if (!isset($responseData["expireTime"])) {
            throw new \DomainException("Response is missing 'expireTime' field");
        }

        return new FetchAccessTokenResponse(
            (string)$responseData["accessToken"],
            $this->parseRFC3339Timestamp((string)$responseData["expireTime"])->getTimestamp(),
            implode(" ", $scopes),
            "Bearer",
        );
    }

    /**
     * Fetches an access token using the IAM Credentials REST API
     * {@link https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken
     * generateIdToken} endpoint.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed ID token.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse {
        $params = [
            "audience"     => $audience,
            "includeEmail" => true,
        ];

        if (!empty($this->delegates)) {
            $params["delegates"] = $this->delegates;
        }

        $responseData = $this->sendIAMCredentialsRequest(
            \sprintf(self::IDENTITY_TOKEN_URI, $this->target),
            $params,
        );

        return new FetchIdentityTokenResponse((string)$responseData["token"]);
    }

    /**
     * Not supported.
     */
    public function fetchProjectID(): string {
        throw new \BadMethodCallException(__CLASS__ . " does not support " . __FUNCTION__);
    }

    /**
     * Returns the impersonated service account email.
     *
     * @return string
     */
    public function fetchServiceAccountEmail(): string {
        return $this->target;
    }

    /**
     * Generates a signature using the IAM Credentials REST API
     * {@link https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signBlob
     * signBlob} endpoint.
     *
     * @param string $toSign The bytes to sign. The string is sent base64 encoded.
     *
     * @return GenerateSignatureResponse
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse {
        $params = [
            "payload" => \base64_encode($toSign)
        ];

        if (!empty($this->delegates)) {
            $params["delegates"] = $this->delegates;
        }

        $responseData = $this->sendIAMCredentialsRequest(
            \sprintf(self::SIGN_BLOB_URI, $this->target),
            $params,
        );

        return new GenerateSignatureResponse(
            (string)$responseData["keyId"],
            (string)$responseData["signedBlob"],
        );
    }

    /**
     * Returns true if this class supports the given capability.
     */
    public function supportsCapability(string $capability): bool {
        switch ($capability) {
            case Credentials::CAN_FETCH_PROJECT_ID:
                return false;

            case Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL:
                return true;

            case Credentials::CAN_GENERATE_SIGNATURE:
                return true;
        }
    }

    private function sendIAMCredentialsRequest(string $uri, array $params): array {
        $sourceAccessToken = $this->source
            ->fetchAccessToken(self::IAM_CREDENTIALS_SCOPES)
            ->getAccessToken();

        $response = $this->httpClient->send(new Request(
            "POST",
            self::SERVICE_ENDPOINT . $uri,
            [
                "Accept"        => "application/json",
                "Authorization" => "Bearer {$sourceAccessToken}",
                "Content-Type"  => "application/json",
            ],
            \json_encode($params),
        ));

        $responseBody = (string)$response->getBody();

        return (array)\json_decode($responseBody, true, 16, JSON_THROW_ON_ERROR);
    }

    /**
     * Returns additional data about this particular instance to avoid cache collisions for other impersonated accounts.
     *
     * @return string[]
     */
    public function extendCacheKey(): array {
        return [
            \get_class($this->source),
            $this->target,
            ...$this->delegates,
        ];
    }

}
