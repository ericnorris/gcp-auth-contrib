<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Contracts;


/**
 * Classes implementing the ExpiresAt interface expire at a given {@see \DateTimeImmutable}.
 */
interface ExpiresAt {

    /**
     * Returns the {@see \DateTimeImmutable} at which this item expires.
     */
    public function getExpiresAtDateTime(): \DateTimeImmutable;

}
