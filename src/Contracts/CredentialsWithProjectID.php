<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Contracts;


/**
 * Credentials implementing the CredentialsWithProjectID interface can also fetch the Google Cloud Platform project ID
 * that the credentials are associated with.
 */
interface CredentialsWithProjectID extends Credentials {

    /**
     * Returns the project ID.
     *
     * @return string
     */
    public function fetchProjectID(): string;

}
