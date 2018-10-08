<?php
declare(strict_types=1);

class HmacFilterTest extends \Codeception\Test\Unit
{

    private function getAction(): \yii\base\Action
    {
        return new \yii\base\InlineAction('test', new \yii\web\Controller('id', \Yii::$app), 'actionTest');
    }

    public function testInvalidConfig1(): void
    {
        $this->expectException(\yii\base\InvalidConfigException::class);
        new \SamIT\Yii2\UrlSigner\HmacFilter();
    }

    public function testInvalidConfig2(): void
    {
        $this->expectException(\yii\base\InvalidConfigException::class);
        new \SamIT\Yii2\UrlSigner\HmacFilter([
            'signer' => new stdClass()
        ]);
    }

    public function testValidConfig(): void
    {
        $filter = new \SamIT\Yii2\UrlSigner\HmacFilter([
            'signer' => new SamIT\Yii2\UrlSigner\UrlSigner(['secret' => 'test123'])
        ]);
        $this->assertInstanceOf(\SamIT\Yii2\UrlSigner\HmacFilter::class, $filter);
    }

    public function testVerifyFalse(): void
    {
        $filter = new \SamIT\Yii2\UrlSigner\HmacFilter([
            'signer' => new SamIT\Yii2\UrlSigner\UrlSigner(['secret' => 'test123'])
        ]);


        $this->expectException(\yii\web\ForbiddenHttpException::class);
        $filter->beforeAction($this->getAction());
    }

    public function testVerifyTrue(): void
    {
        $mock = $this->make(SamIT\Yii2\UrlSigner\UrlSigner::class, [
            'verify' => \Codeception\Stub\Expected::once(function() {
                return true;
            })
        ]);

        $filter = new \SamIT\Yii2\UrlSigner\HmacFilter([
            'signer' => $mock
        ]);


        $this->assertTrue($filter->beforeAction($this->getAction()));
    }
}