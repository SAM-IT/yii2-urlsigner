<?php
declare(strict_types=1);


namespace SamIT\Yii2\UrlSigner;


use SamIT\Yii2\UrlSigner\UrlSigner;
use yii\base\ActionFilter;
use yii\base\InvalidConfigException;
use yii\web\ForbiddenHttpException;
use yii\web\Request;

/**
 * Filter that checks for a valid HMAC in the URL.
 * @inheritdoc
 */
class HmacFilter extends ActionFilter
{
    /**
     * @var UrlSigner
     */
    public $signer;

    public function init(): void
    {
        parent::init();
        if (!$this->signer instanceof UrlSigner) {
            throw new InvalidConfigException('Signer is required');
        }
    }


    /**
     * @param \yii\base\Action $action
     * @throws \Exception
     * @return bool
     */
    public function beforeAction($action)
    {
        /**
         * We obtain the request this way because we do not want to store a reference to any objects with state.
         * @var Request $request
         */
        $request = $action->controller->module->get('request');
        $this->signer->verify($request->queryParams, $action->controller->route);
        return true;
    }

}
