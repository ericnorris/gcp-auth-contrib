<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use GuzzleHttp\ClientInterface;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Internal\Credentials\OAuth2Credentials;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;


class AuthorizedUserCredentials extends OAuth2Credentials implements Credentials {

    const REFRESH_TOKEN_GRANT_TYPE = "refresh_token";


    /** @var string */
    private $clientId;

    /** @var string */
    private $clientSecret;

    /** @var string */
    private $refreshToken;

    /** @var ?string */
    private $quotaProject;


    public function __construct(ClientInterface $httpClient, array $credentials) {
        parent::__construct($httpClient);

        if (!self::isAuthorizedUserCredentials($credentials)) {
            throw new \InvalidArgumentException("Argument does not appear to be OAuth2 credentials");
        }

        $this->clientId     = (string)($credentials["client_id"] ?? "");
        $this->clientSecret = (string)($credentials["client_secret"] ?? "");
        $this->refreshToken = (string)($credentials["refresh_token"] ?? "");
        $this->quotaProject = isset($credentials["quota_project_id"]) ? (string)$credentials["quota_project_id"] : null;

        if (empty($this->clientId)) {
            throw new \InvalidArgumentException("OAuth2 credentials has missing or empty 'client_id' field");
        }

        if (empty($this->clientSecret)) {
            throw new \InvalidArgumentException("OAuth2 credentials has missing or empty 'client_secret' field");
        }

        if (empty($this->refreshToken)) {
            throw new \InvalidArgumentException("OAuth2 credentials has missing or empty 'refresh_token' field");
        }
    }

    public static function isAuthorizedUserCredentials(array $credentials): bool {
        return ($credentials["type"] ?? "") === "authorized_user";
    }

    /**
     * Not supported.
     */
    public function fetchProjectID(): string {
        throw new \BadMethodCallException(__CLASS__ . " does not support " . __FUNCTION__);
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
            default:
                return false;
        }
    }

    protected function getOAuth2GrantType(): string {
        return self::REFRESH_TOKEN_GRANT_TYPE;
    }

    protected function assertClaims(array $claims): array {
        return array_merge([
            "client_id"     => $this->clientId,
            "client_secret" => $this->clientSecret,
            "refresh_token" => $this->refreshToken,
        ], $claims);
    }

}
