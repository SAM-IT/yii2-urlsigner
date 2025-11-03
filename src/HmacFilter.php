<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner;

use yii\base\ActionFilter;
use yii\base\InvalidConfigException;
use yii\web\Request;

/**
 * Filter that checks for a valid HMAC in the URL.
 */
final class HmacFilter extends ActionFilter
{
    private bool $locked = false;

    public UrlSignerComponent|UrlSigner $signer {
        set {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->signer = $value;
        }

        get {
            if (! isset($this->signer)) {
                throw new InvalidConfigException('Signer must be set');
            }
            return $this->signer;
        }

    }

    /**
     * @template T of \yii\base\Controller
     * @param \yii\base\Action<T> $action
     * @throws \Exception
     */
    public function beforeAction($action): bool
    {
        /**
         * We obtain the request this way because we do not want to store a reference to any objects with state.
         */
        $request = $action->controller->request;
        if (! $request instanceof Request) {
            throw new InvalidConfigException('Invalid request object');
        }
        $this->signer->verify($request->queryParams, $action->controller->route);
        return true;
    }
}
