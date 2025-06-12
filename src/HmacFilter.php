<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner;

use yii\base\ActionFilter;
use yii\base\InvalidConfigException;
use yii\web\Request;

/**
 * Filter that checks for a valid HMAC in the URL.
 */
class HmacFilter extends ActionFilter
{
    public null|UrlSigner $signer = null;

    /**
     * @param \yii\base\Action $action
     * @throws \Exception
     */
    public function beforeAction($action): bool
    {
        $signer = $this->signer;
        if (! isset($signer)) {
            throw new InvalidConfigException('Signer is required');
        }

        /**
         * We obtain the request this way because we do not want to store a reference to any objects with state.
         */
        $request = $action->controller->request;
        if (! $request instanceof Request) {
            throw new InvalidConfigException('Invalid request object');
        }
        $signer->verify($request->queryParams, $action->controller->route);
        return true;
    }
}
