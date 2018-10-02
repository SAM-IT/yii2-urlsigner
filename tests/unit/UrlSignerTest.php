<?php
declare(strict_types=1);

class UrlSignerTest extends \Codeception\Test\Unit
{
    public function testInvalidConfig(): void
    {
        $this->expectException(\yii\base\InvalidConfigException::class);
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner();

    }
    public function testSimple(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);

        $params = [
            '/url',
            'test' => 'abc'
        ];
        $signer->signParams($params, false);

        $this->assertArrayHasKey($signer->hmacParam, $params);
        $this->assertArrayHasKey($signer->expirationParam, $params);
        $this->assertArrayNotHasKey($signer->paramsParam, $params);
        $route = $params[0];
        unset($params[0]);
        $this->assertTrue($signer->verify($params, $route));
    }

    public function testAdditions(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);

        $params = [
            '/url',
            'test' => 'abc'
        ];
        $signer->signParams($params, true);

        $this->assertArrayHasKey($signer->hmacParam, $params);
        $this->assertArrayHasKey($signer->expirationParam, $params);
        $this->assertArrayHasKey($signer->paramsParam, $params);
        $route = $params[0];
        unset($params[0]);
        $this->assertTrue($signer->verify($params, $route));
        $params['extra'] = 'cool';
        $this->assertTrue($signer->verify($params, $route));
    }

    public function testDoubleSign(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);

        $params = [
            '/url',
            'test' => 'abc'
        ];
        $signer->signParams($params, true);
        $this->expectException(RuntimeException::class);
        $signer->signParams($params, true);

    }

    public function testMissingHmac(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);
        $params = [
            '/url',
            'test' => 'abc'
        ];
        $signer->signParams($params, false);

        $this->assertArrayHasKey($signer->hmacParam, $params);
        $this->assertArrayHasKey($signer->expirationParam, $params);
        $this->assertArrayNotHasKey($signer->paramsParam, $params);
        $route = $params[0];
        unset($params[0]);
        $this->assertTrue($signer->verify($params, $route));
        unset($params[$signer->hmacParam]);
        $this->assertFalse($signer->verify($params, $route));
    }

    public function testModification(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);
        $params = [
            '/url',
            'test' => 'abc'
        ];
        $signer->signParams($params, false);

        $this->assertArrayHasKey($signer->hmacParam, $params);
        $this->assertArrayHasKey($signer->expirationParam, $params);
        $this->assertArrayNotHasKey($signer->paramsParam, $params);
        $route = $params[0];
        unset($params[0]);

        $params['test'] = 'abd';
        $this->assertFalse($signer->verify($params, $route));
    }

    public function testRelativeRoute(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);

        $params = [
            'controller/action',
            'test' => 'abc'
        ];
        $this->expectException(RuntimeException::class);
        $signer->signParams($params);
    }

    public function testMissingExpiration(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);

        $params = [
            '/controller/action',
            'test' => 'abc'
        ];
        $signer->signParams($params);

        unset($params[$signer->expirationParam]);
        $this->assertFalse($signer->verify($params, '/controller/action'));
    }

    public function testNoExpiration(): void
    {
        $signer = new SamIT\Yii2\UrlSigner\UrlSigner([
            'secret' => 'test123'
        ]);
        $expirationParam = $signer->expirationParam;
        $signer->expirationParam = null;

        $params = [
            '/controller/action',
            'test' => 'abc'
        ];
        $signer->signParams($params);
        $this->assertNotContains($expirationParam, $params);

        $this->assertTrue($signer->verify($params, '/controller/action'));
        $signer->expirationParam = $expirationParam;
        $this->assertTrue($signer->verify($params, '/controller/action'));
    }
}