<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner\Tests;

use DateInterval;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\Clock\SystemClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\TestCase;
use SamIT\Yii2\UrlSigner\exceptions\UrlVerificationException;
use SamIT\Yii2\UrlSigner\UrlSigner;

#[CoversClass(UrlSigner::class)]
class UrlSignerTest extends TestCase
{
    #[DoesNotPerformAssertions]
    public function testSimple(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );

        $signed = $signer->sign('/url', ['test' => 'abc'], false);

        $signer->verify($signed, '/url');
    }

    #[DoesNotPerformAssertions]
    public function testAdditions(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );

        $route = '/url';
        $signed = $signer->sign('/url', ['test' => 'abc'], true);

        $signer->verify($signed, $route);
        $signed['extra'] = 'cool';
        $signer->verify($signed, $route);
    }

    public function testDoubleSign(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );

        $signer->sign('/url', ['test' => 'abc']);
        $this->expectException(\InvalidArgumentException::class);
        $signer->sign('/url', ['test' => 'abc', 'hmac' => 'abc']);

    }

    public function testMissingHmac(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );
        $route = '/url';
        $signed = $signer->sign('/url', ['test' => 'abc'], false);

        $signer->verify($signed, $route);
        unset($signed['hmac']);
        $this->expectException(UrlVerificationException::class);
        $signer->verify($signed, $route);
    }

    public function testModification(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );
        $signed = $signer->sign('/url', ['test' => 'abc'], false);

        $signed['test'] = 'abd';
        $this->expectException(UrlVerificationException::class);
        $signer->verify($signed, '/url');
    }

    public function testRelativeRoute(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );

        $this->expectException(\InvalidArgumentException::class);
        $signer->sign('controller/action', []);
    }

    public function testMissingExpiration(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
        );

        $params = ['test' => 'abc'];
        $signed = $signer->sign('/controller/action', $params);

        unset($signed['expires']);
        $this->expectException(UrlVerificationException::class);
        $signer->verify($params, '/controller/action');
    }

    public function testDefaultExpiration(): void
    {
        $signer = new UrlSigner(
            clock: SystemClock::fromUTC(),
            secret: 'test123',
            defaultExpirationInterval: new DateInterval('P14D')
        );
        $signed = $signer->sign('/controller/action', [], false);
        $this->assertGreaterThan(\time() + 14 * 24 * 3600 - 100, $signed['expires']);
    }

    public function testTimeMocking(): void
    {
        $clock = FrozenClock::fromUTC();
        $signer = new UrlSigner(
            clock: $clock,
            secret: 'test123',
            defaultExpirationInterval: new DateInterval('PT01S')
        );
        $signed = $signer->sign('/controller/action', []);
        $this->assertContains('expires', $signed);
        $this->assertSame($clock->now()->getTimestamp() + 1, $signed['expires']);
        $clock->adjustTime('-10 seconds');
        $signer->verify($signed, '/controller/action');
        $clock->adjustTime('+10 seconds');
        $signer->verify($signed, '/controller/action');
        $clock->adjustTime('+10 seconds');
        $this->expectException(UrlVerificationException::class);
        $signer->verify($signed, '/controller/action');
    }
}
