<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Response;


/**
 * The GenerateSignatureResponse class is a plain data object codifying the expected properties for a signature.
 *
 * @psalm-immutable
 */
class GenerateSignatureResponse {

    /** @var string */
    private $keyID;

    /** @var string */
    private $signature;


    public function __construct(string $keyID, string $signature) {
        $this->keyID     = $keyID;
        $this->signature = $signature;
    }

    public function getKeyID(): string {
        return $this->keyID;
    }

    public function getSignature(): string {
        return $this->signature;
    }

}
