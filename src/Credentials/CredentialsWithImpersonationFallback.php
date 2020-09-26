<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Credentials;

use Fig\Http\Message\StatusCodeInterface;
use GuzzleHttp\Exception\ClientException;

use ericnorris\GCPAuthContrib\Contracts\Credentials;
use ericnorris\GCPAuthContrib\Credentials\ImpersonatedCredentials;
use ericnorris\GCPAuthContrib\CredentialsFactory;
use ericnorris\GCPAuthContrib\Response\FetchAccessTokenResponse;
use ericnorris\GCPAuthContrib\Response\FetchIdentityTokenResponse;
use ericnorris\GCPAuthContrib\Response\GenerateSignatureResponse;


/**
 * The CredentialsWithImpersonationFallback class, besides being overly descriptive, fills in the gap for credentials
 * that may not support particular capabilities by invoking the {@link
 * https://cloud.google.com/iam/docs/reference/credentials/rest IAM Credentials REST API} via the {@see
 * ImpersonatedCredentials} class.
 *
 * The {@see MetadataServerCredentials} class benefits from this as it does not support the generateSignature method,
 * and in some cases does not support the fetchIdentityToken method.
 */
class CredentialsWithImpersonationFallback implements Credentials {


    /** @var Credentials */
    private $source;

    /** @var CredentialsFactory */
    private $credentialsFactory;

    /** @var ?string */
    private $fallbackAccount;

    /** @var ?ImpersonatedCredentials */
    private $lazyImpersonatedCredentials;


    /**
     * @param Credentials $source The source credentials to use as a primary method of authentication.
     * @param CredentialsFactory $factory A credentials factory for creating {@see ImpersonatedCredentials}
     * @param ?string $fallbackAccount The email of the service account to fallback to, or null to use the service
     *        account email associated with the source credentials.
     */
    public function __construct(Credentials $source, CredentialsFactory $factory, ?string $fallbackAccount = null) {
        $this->source             = $source;
        $this->credentialsFactory = $factory;
        $this->fallbackAccount    = $fallbackAccount;
    }

     /**
     * Fetches an access token from the underlying source credentials.
     *
     * @param string[] $scopes An array of scopes to request.
     *
     * @return FetchAccessTokenResponse
     */
    public function fetchAccessToken(array $scopes = []): FetchAccessTokenResponse {
        return $this->source->fetchAccessToken($scopes);
    }

    /**
     * Fetches an identity token from the underlying source credentials, or via a fallback if the source experiences
     * an HTTP 404 Not Found exception.
     *
     * @param string $audience The desired 'aud' claim in the Google-signed ID token.
     *
     * @return FetchIdentityTokenResponse
     */
    public function fetchIdentityToken(string $audience): FetchIdentityTokenResponse {
        try {
            return $this->source->fetchIdentityToken($audience);
        } catch (ClientException $ex) {
            $response = $ex->getResponse();

            if (!$response || $response->getStatusCode() !== StatusCodeInterface::STATUS_NOT_FOUND) {
                throw $ex;
            }

            return $this->getLazyImpersonatedCredentials()->fetchIdentityToken($audience);
        }
    }

    /**
     * Fetches the project ID from underlying source credentials.
     *
     * @return string
     */
    public function fetchProjectID(): string {
        return $this->source->fetchProjectID();
    }

    /**
     * Returns the configured fallback account or fetches the service account from the underlying source credentials.
     *
     * @return string
     */
    public function fetchServiceAccountEmail(): string {
        return $this->fallbackAccount ?? $this->source->fetchServiceAccountEmail();
    }

    /**
     * Generates a signature using the source credentials if possible, or via a fallback.
     *
     * @param string $toSign
     *
     * @return GenerateSignatureResponse
     */
    public function generateSignature(string $toSign): GenerateSignatureResponse {
        if ($this->source->supportsCapability(Credentials::CAN_GENERATE_SIGNATURE)) {
            return $this->source->generateSignature($toSign);
        }

        return $this->getLazyImpersonatedCredentials()->generateSignature($toSign);
    }

    /**
     * Returns true if this class supports the given capability.
     */
    public function supportsCapability(string $capability): bool {
        switch ($capability) {
            case Credentials::CAN_FETCH_PROJECT_ID:
                return $this->source->supportsCapability($capability);

            case Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL:
                return $this->source->supportsCapability($capability) ||
                    $this->fallbackAccount;

            case Credentials::CAN_GENERATE_SIGNATURE:
                return $this->source->supportsCapability(Credentials::CAN_GENERATE_SIGNATURE) ||
                    $this->source->supportsCapability(Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL) ||
                    $this->fallbackAccount;
        }
    }

    private function getLazyImpersonatedCredentials(): ImpersonatedCredentials {
        if ($this->lazyImpersonatedCredentials !== null) {
            return $this->lazyImpersonatedCredentials;
        }

        if ($this->fallbackAccount !== null) {
            $sourceEmail = $this->fallbackAccount;
        } else if ($this->source->supportsCapability(Credentials::CAN_FETCH_SERVICE_ACCOUNT_EMAIL)) {
            $sourceEmail = $this->source->fetchServiceAccountEmail();
        } else {
            throw new \BadMethodCallException("Could not find service account email to fallback to.");
        }

        return $this->lazyImpersonatedCredentials = $this->credentialsFactory->makeImpersonatedCredentials(
            $this->source,
            $sourceEmail,
        );
    }

}
