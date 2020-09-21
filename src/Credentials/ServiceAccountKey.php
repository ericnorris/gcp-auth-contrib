<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;

use ericnorris\GCPAuthContrib\Contracts\CredentialsWithProjectID;
use ericnorris\GCPAuthContrib\Internal\Credentials\OAuth2Credentials;
use ericnorris\GCPAuthContrib\Time;


/**
 * The ServiceAccountKey class uses a private key for a Google Cloud Platform (GCP) service account to sign OAuth2
 * "JWT bearer" authorization grant requests.
 */
class ServiceAccountKey extends OAuth2Credentials implements CredentialsWithProjectID {

    const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    const JWT_EXPIRY_INTERVAL   = "PT600S";
    const JWT_SIGNING_ALGORITHM = "RS256";


    /** @var string */
    private $clientEmail;

    /** @var string */
    private $privateKey;

    /** @var string */
    private $projectID;


    public function __construct(ClientInterface $httpClient, array $serviceAccountKey) {
        parent::__construct($httpClient);

        if (!self::isServiceAccountKey($serviceAccountKey)) {
            throw new \InvalidArgumentException("Argument does not appear to be a service account key");
        }

        $this->clientEmail = (string)($serviceAccountKey["client_email"] ?? "");
        $this->privateKey  = (string)($serviceAccountKey["private_key"] ?? "");
        $this->projectID   = (string)($serviceAccountKey["project_id"] ?? "");

        if (empty($this->clientEmail)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'client_email' field");
        }

        if (empty($this->privateKey)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'private_key' field");
        }

        if (empty($this->projectID)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'project_id' field");
        }
    }

    public static function isServiceAccountKey(array $serviceAccountKey): bool {
        return ($serviceAccountKey["type"] ?? "") === "service_account";
    }

    public function fetchProjectID(): string {
        return $this->projectID;
    }

    protected function getOAuth2GrantType(): string {
        return self::JWT_BEARER_GRANT_TYPE;
    }

    protected function assertClaims(array $claims): array {
        $iat = Time::now();
        $exp = $iat->add(new \DateInterval(self::JWT_EXPIRY_INTERVAL));

        $payload = \array_merge([
            "iss" => $this->clientEmail,
            "iat" => $iat->getTimestamp(),
            "exp" => $exp->getTimestamp(),
            "aud" => self::OAUTH2_AUTHORIZATION_ENDPOINT,
        ], $claims);

        $assertion = JWT::encode(
            $payload,
            $this->privateKey,
            self::JWT_SIGNING_ALGORITHM,
        );

        return [
            "assertion"  => $assertion,
        ];
    }

}
