<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Internal\Credentials;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Request;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Time;


/**
 * Classes extending OAuth2Credentials can fetch a short-lived access token or Google-signed identity token
 * using an OAuth2 grant type.
 */
abstract class OAuth2Credentials implements Credentials {

    const OAUTH2_AUTHORIZATION_ENDPOINT = "https://oauth2.googleapis.com/token";


    /** @var ClientInterface */
    private $httpClient;


    public function __construct(ClientInterface $httpClient) {
        $this->httpClient = $httpClient;
    }

    /**
     * Fetches an access token from the OAuth2 token endpoint.
     *
     * @param string[] $scopes An array of scopes to request from the OAuth2 token endpoint.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        $claims = [
            "scope" => implode(" ", $scopes),
        ];

        if (!empty($scopes)) {
            $claims["scope"] = implode(" ", $scopes);
        }

        $responseData = $this->sendOAuth2Request($claims);

        if (!isset($responseData["expires_in"])) {
            throw new \DomainException("Response is missing 'expires_in' field");
        }

        return new FetchAccessTokenResponse(
            (string)$responseData["access_token"],
            Time::calculateExpiresAt((int)$responseData["expires_in"])->getTimestamp(),
            (string)($responseData["scope"] ?? ""),
            (string)$responseData["token_type"],
        );
    }

    /**
     * Fetches an identity token from the OAuth2 token endpoint.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed ID token.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse {
        $claims = [
            "target_audience" => $audience,
        ];

        $responseData = $this->sendOAuth2Request($claims);

        return new FetchIdentityTokenResponse((string)$responseData["id_token"]);
    }

    private function sendOAuth2Request(array $claims): array {
        $params = [
            "grant_type" => $this->getOAuth2GrantType(),
        ] + $this->assertClaims($claims);

        $response = $this->httpClient->send(new Request(
            "POST",
            self::OAUTH2_AUTHORIZATION_ENDPOINT,
            [
                "Accept"       => "application/json",
                "Content-Type" => "application/x-www-form-urlencoded",
            ],
            \http_build_query($params),
        ));

        $responseBody = (string)$response->getBody();

        return (array)\json_decode($responseBody, true, 16, JSON_THROW_ON_ERROR);
    }

    /**
     * Returns the OAuth2 grant type this credentials implementation uses.
     *
     * @return string
     */
    abstract protected function getOAuth2GrantType(): string;

    /**
     * Returns an array that asserts the given claims for this particular credentials implementation.
     *
     * @param array $claims
     *
     * @return array
     */
    abstract protected function assertClaims(array $claims): array;

}
