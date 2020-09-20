<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Response;

use ericnorris\GCPAuthContrib\Contracts\ExpiresAt;


/**
 * The FetchIdentityTokenResponse class is a plain data object codifying the expected properties in an identity token
 * retrieved from the {@see Credentials::fetchIdentityToken} method.
 *
 * It implements {@see \ArrayAccess} in order to function as a normal array for code that expects it.
 *
 * @psalm-immutable
 */
class FetchIdentityTokenResponse implements \ArrayAccess, ExpiresAt {

    /** @var string */
    private $id_token;

    /** @var int */
    private $expires_at;


    public function __construct(string $idToken) {
        if (empty($idToken)) {
            throw new \InvalidArgumentException("\$idToken argument cannot be empty");
        }

        $this->id_token   = $idToken;
        $this->expires_at = self::parseExpirationFieldUnsafely($idToken);
    }

    /**
     * Returns the value of the "exp" field from the identity token _without_ validating that it is genuine.
     *
     * @param string $idToken The identity token.
     *
     * @return int
     */
    private static function parseExpirationFieldUnsafely(string $idToken): int {
        $parts = \explode(".", $idToken, 3);

        if (count($parts) != 3) {
            throw new \InvalidArgumentException("\$idToken argument does not appear to be a JWT");
        }

        $payloadJSON = \base64_decode($parts[1]);
        $payload     = (array)\json_decode($payloadJSON, true, 16, JSON_THROW_ON_ERROR);

        if (empty($payload["exp"])) {
            throw new \InvalidArgumentException("\$idToken argument has empty or missing 'exp' field");
        }

        return (int)$payload["exp"];
    }

    public function getIdentityToken(): string {
        return $this->id_token;
    }

    public function getExpiresAt(): int {
        return $this->expires_at;
    }

    public function getExpiresAtDateTime(): \DateTimeImmutable {
        return new \DateTimeImmutable("@{$this->expires_at}");
    }

    public function offsetExists($offset): bool {
        return isset($this->$offset);
    }

    /**
     * @return mixed
     */
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
