<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner\Tests;

use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\TestCase;
use SamIT\Yii2\UrlSigner\UrlSignerComponent;
use yii\base\InvalidConfigException;
use yii\web\ForbiddenHttpException;

#[CoversClass(UrlSignerComponent::class)]
class UrlSignerComponentTest extends TestCase
{
    public function testInvalidConfigMissingSecret(): void
    {
        $this->expectException(InvalidConfigException::class);
        $signer = new UrlSignerComponent();
    }

    /**
     * @return iterable<array{0: array{secret: string, hmacParam: string, paramsParam: string, expirationParam: string}}>
     */
    public static function configurationProvider(): iterable
    {
        $config = ['secret' => 'test123', 'hmacParam' => 'hmac', 'paramsParam' => 'params', 'expirationParam' => 'expires'];
        foreach (array_keys($config) as $value) {
            yield [[
                ...$config,
                $value => ''
            ]];
        }

    }

    /**
     * @param array{secret: string, hmacParam: string, paramsParam: string, expirationParam: string} $config
     */
    #[DataProvider('configurationProvider')]
    public function testInvalidConfigEmptyParameter(array $config): void
    {
        $this->expectException(InvalidConfigException::class);
        $signer = new UrlSignerComponent($config);
    }

    public function testSimple(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123'
        ]);

        $route = '/url';
        $signed = $signer->sign('/url', ['test' => 'abc'], false);

        $this->assertArrayHasKey($signer->hmacParam, $signed);
        $this->assertArrayHasKey($signer->expirationParam, $signed);
        $this->assertArrayNotHasKey($signer->paramsParam, $signed);

        unset($signed[0]);
        $signer->verify($signed, $route);
    }

    #[DoesNotPerformAssertions]
    public function testAdditions(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123'
        ]);

        $route = '/url';
        $signed = $signer->sign($route, ['test' => 'abc'], true);

        unset($signed[0]);
        $signer->verify($signed, $route);
        $signed['extra'] = 'cool';
        $signer->verify($signed, $route);
    }

    public function testDoubleSign(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123'
        ]);

        $signed = $signer->sign('/url', ['test' => 'abc']);
        $this->expectException(\InvalidArgumentException::class);
        unset($signed[0]);
        $signer->sign('/url', $signed);

    }

    public function testMissingHmac(): void
    {
        $signer = new UrlSignerComponent([
            "secret" => 'test123',
        ]);
        $route = '/url';
        $signed = $signer->sign('/url', ['test' => 'abc'], false);

        $signer->verify($signed, $route);
        unset($signed['hmac']);
        $this->expectException(ForbiddenHttpException::class);
        $signer->verify($signed, $route);
    }

    public function testModification(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123'
        ]);
        $route = '/url';
        $signed = $signer->sign($route, ['test' => 'abc'], false);

        unset($signed[0]);

        $signed['test'] = 'abd';
        $this->expectException(ForbiddenHttpException::class);
        $signer->verify($signed, $route);
    }

    public function testRelativeRoute(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123'
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $signer->sign('controller/action', []);
    }

    public function testMissingExpiration(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123'
        ]);

        $signed = $signer->sign('/controller/action', ['test' => 'abc']);

        unset($signed['expires']);
        $this->expectException(ForbiddenHttpException::class);
        $signer->verify($signed, '/controller/action');
    }

    public function testDefaultExpiration(): void
    {
        $signer = new UrlSignerComponent([
            'secret' => 'test123',
            'defaultExpirationInterval' => 'P14D'
        ]);
        $signed = $signer->sign('/controller/action', []);
        $this->assertContains('expires', $signed);
        $this->assertGreaterThan(\time() + 14 * 24 * 3600 - 100, $signed['expires']);
    }

    public function testTimeMocking(): void
    {
        $clock = FrozenClock::fromUTC();
        $signer = new UrlSignerComponent([
            "secret" => 'test123',
            "defaultExpirationInterval" => 'PT01S',
            "clock" => $clock,
        ]);
        $signed = $signer->sign('/controller/action', []);
        $this->assertContains('expires', $signed);
        $this->assertSame($clock->now()->getTimestamp() + 1, $signed['expires']);
        $clock->adjustTime('-10 seconds');
        $signer->verify($signed, '/controller/action');
        $clock->adjustTime('+10 seconds');
        $signer->verify($signed, '/controller/action');
        $clock->adjustTime('+10 seconds');
        $this->expectException(ForbiddenHttpException::class);
        $signer->verify($signed, '/controller/action');
    }
}
