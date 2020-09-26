<?php declare(strict_types=1);

namespace ericnorris\GCPAuthContrib\Tests;

use GuzzleHttp\ClientInterface;
use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Spatie\Snapshots\MatchesSnapshots;


trait MatchesRequestSnapshots {
    use MatchesSnapshots;


    /** @var Request[] */
    private $requestHistory = [];

    /**
     * @var Response[] $recordedResponses An array of responses that will be replayed to the caller
     *
     * @return ClientInterface
     */
    protected function makeSnapshotClient(array $recordedResponses): ClientInterface {
        $historyMiddleware = \GuzzleHttp\Middleware::history($this->requestHistory);
        $fakeHandler       = new \GuzzleHttp\Handler\MockHandler($recordedResponses);

        $fakeStack = \GuzzleHttp\HandlerStack::create($fakeHandler);
        $fakeStack->push($historyMiddleware);

        return new \GuzzleHttp\Client([
            "handler" => $fakeStack,
            "headers" => [
                "user-agent" => "ericnorris/gcp-auth-contrib unit test"
            ],
        ]);
    }

    protected function assertRequestHistoryMatchesSnapshot() {
        foreach (array_column($this->requestHistory, "request") as $request) {
            $this->assertMatchesSnapshot(\GuzzleHttp\Psr7\str($request));
        }
    }

    protected function getSnapshotDirectory(): string {
        return __DIR__ . "/../snapshots";
    }

}
