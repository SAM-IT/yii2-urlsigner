<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SamIT\Yii2\UrlSigner\HmacFilter;
use SamIT\Yii2\UrlSigner\UrlSignerComponent;
use yii\base\Action;
use yii\base\Controller;
use yii\base\InvalidConfigException;
use yii\base\Module;
use yii\web\ForbiddenHttpException;
use yii\web\Request;
use yii\web\Response;

#[CoversClass(HmacFilter::class)]
final class HmacFilterTest extends TestCase
{
    private function getAction(): Action
    {
        $module = new Module('test');
        $action = new Action('test', new Controller('id', $module, [
            'request' => new Request(),
            'response' => new Response([
                'charset' => 'utf-8'
            ])
        ]));
        return $action;
    }

    public function testInvalidConfig1(): void
    {
        $this->expectException(InvalidConfigException::class);
        $filter = new HmacFilter();
        $filter->beforeAction($this->getAction());
    }

    public function testValidConfig(): void
    {
        $filter = new HmacFilter([
            'signer' => new UrlSignerComponent(['secret' => 'test123'])
        ]);
        $this->assertInstanceOf(HmacFilter::class, $filter);
    }

    public function testVerifyFalse(): void
    {
        $filter = new HmacFilter([
            'signer' => new UrlSignerComponent(['secret' => 'test123'])
        ]);

        $this->expectException(ForbiddenHttpException::class);
        $filter->beforeAction($this->getAction());
    }

    public function testVerifyTrue(): void
    {
        $signer = new class() extends UrlSignerComponent {
            public function init(): void
            {

            }

            public function verify(array $params, string $route): void
            {

            }
        };

        $filter = new HmacFilter([
            'signer' => $signer
        ]);

        $this->assertTrue($filter->beforeAction($this->getAction()));
    }

    public function testInvalidRequest(): void
    {

        $filter = new HmacFilter();

        $controller = new class('id', new Module('test')) extends Controller {
            public function init(): void
            {
                $this->request = 'test123';
            }
        };
        $this->expectException(InvalidConfigException::class);
        $filter->beforeAction(new Action('test', $controller));
    }
}
