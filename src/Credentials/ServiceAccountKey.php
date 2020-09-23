<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Internal\Credentials\OAuth2Credentials;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;
use ericnorris\GCPAuthContrib\Time;


/**
 * The ServiceAccountKey class uses a private key for a Google Cloud Platform (GCP) service account to sign OAuth2
 * "JWT bearer" authorization grant requests.
 */
class ServiceAccountKey extends OAuth2Credentials implements Credentials {

    const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    const JWT_EXPIRY_INTERVAL   = "PT600S";
    const JWT_SIGNING_ALGORITHM = "RS256";


    /** @var string */
    private $clientEmail;

    /** @var string */
    private $privateKey;

    /** @var string */
    private $privateKeyID;

    /** @var string */
    private $projectID;


    public function __construct(ClientInterface $httpClient, array $serviceAccountKey) {
        parent::__construct($httpClient);

        if (!self::isServiceAccountKey($serviceAccountKey)) {
            throw new \InvalidArgumentException("Argument does not appear to be a service account key");
        }

        $this->clientEmail  = (string)($serviceAccountKey["client_email"] ?? "");
        $this->privateKey   = (string)($serviceAccountKey["private_key"] ?? "");
        $this->privateKeyID = (string)($serviceAccountKey["private_key_id"] ?? "");
        $this->projectID    = (string)($serviceAccountKey["project_id"] ?? "");

        if (empty($this->clientEmail)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'client_email' field");
        }

        if (empty($this->privateKey)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'private_key' field");
        }

        if (empty($this->privateKeyID)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'private_key_id' field");
        }

        if (empty($this->projectID)) {
            throw new \InvalidArgumentException("Service account key has missing or empty 'project_id' field");
        }
    }

    public static function isServiceAccountKey(array $serviceAccountKey): bool {
        return ($serviceAccountKey["type"] ?? "") === "service_account";
    }

    /**
     * Fetches the project ID from the service account key file.
     *
     * @return string
     */
    public function fetchProjectID(): string {
        return $this->projectID;
    }

    /**
     * Fetches the service account email from the service account key file.
     *
     * @return string
     */
    public function fetchServiceAccountEmail(): string {
        return $this->clientEmail;
    }

    /**
     * Generates a signature using the service account's private key.
     *
     * @param string $toSign The bytes to sign.
     *
     * @return GenerateSignatureResponse
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse {
        if (!extension_loaded("openssl")) {
            throw new \RuntimeException("'openssl' extension is missing, cannot generate signature.");
        }

        $signature = "";

        if (!openssl_sign($toSign, $signature, $this->privateKey, "sha256WithRSAEncryption")) {
            throw new \RuntimeException("Could not generate signature with 'openssl': " . \openssl_error_string());
        }

        return new GenerateSignatureResponse($this->privateKeyID, \base64_encode($signature));
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
