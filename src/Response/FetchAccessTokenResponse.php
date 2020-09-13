<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Response;

use ericnorris\GCPAuthContrib\Contracts\ExpiresAt;


/**
 * The FetchAccessTokenResponse class is a plain data object codifying the expected properties in an access token
 * retrieved from the {@see Credentials::fetchAccessToken} method.
 *
 * It implements {@see \ArrayAccess} in order to function as a normal array for code that expects it.
 */
class FetchAccessTokenResponse implements \ArrayAccess, ExpiresAt {

    /** @var string */
    private $access_token;

    /** @var int */
    private $expires_at;

    /** @var string */
    private $scope;

    /** @var string */
    private $token_type;


    public function __construct(string $accessToken, int $expiresAt, string $scope, string $tokenType) {
        if (empty($accessToken)) {
            throw new \InvalidArgumentException("\$accessToken argument cannot be empty");
        }

        if (empty($expiresAt)) {
            throw new \InvalidArgumentException("\$expiresAt argument cannot be empty");
        }

        $this->access_token = $accessToken;
        $this->expires_at   = $expiresAt;
        $this->scope        = $scope;
        $this->token_type   = $tokenType;
    }

    public function getAccessToken(): string {
        return $this->access_token;
    }

    public function getScope(): string {
        return $this->scope;
    }

    public function getExpiresAt(): int {
        return $this->expires_at;
    }

    public function getExpiresAtDateTime(): \DateTimeImmutable {
        return new \DateTimeImmutable("@{$this->expires_at}");
    }

    public function getTokenType(): string {
        return $this->token_type;
    }

    public function offsetExists($offset): bool {
        return isset($this->$offset);
    }

    public function offsetGet($offset) {
        return $this->$offset;
    }

    public function offsetSet($offset, $value): void {
        throw new \RuntimeException(__CLASS__ . " is immutable, cannot set '$offset'");
    }

    public function offsetUnset($offset): void {
        throw new \RuntimeException(__CLASS__ . " is immutable, cannot unset '$offset'");
    }

}
