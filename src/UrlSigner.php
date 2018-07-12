<?php
declare(strict_types=1);


namespace SamIT\Yii2\UrlSigner;


use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\helpers\StringHelper;

class UrlSigner extends Component
{
    /**
     * @var string The name of the URL param for the HMAC
     */
    public $hmacParam = 'hmac';

    /**
     * @var string The name of the URL param for the parameters
     */
    public $paramsParam = 'params';

    /**
     * @var string The name of the URL param for the expiration date time
     */
    public $expirationParam = 'expires';

    /**
     * Note that expiration dates cannot be disabled. If you really need to you can set a longer duration for the links.
     * @var \DateInterval The default interval for link validity (default: 1 week)
     */
    private $_defaultExpirationInterval;

    /**
     * @var string
     */
    public $secret;

    public function init(): void
    {
        parent::init();
        $this->setDefaultExpirationInterval('P7D');
        if (empty($this->secret)
            || empty($this->hmacParam)
            || empty($this->paramsParam)
            || empty($this->expirationParam)
        ) {
            throw new InvalidConfigException('The following configuration params are required: secret, hmacParam, paramsParam and expirationParam');
        }


    }

    public function setDefaultExpirationInterval(string $interval): void
    {
        $this->_defaultExpirationInterval = new \DateInterval($interval);

    }
    /**
     * Calculates the HMAC for a URL.
     **/
    public function calculateHMAC(
        array $params,
        string $route
    ): string {
        if (isset($params[0])) {
            unset($params[0]);
        }

        \ksort($params);

        $hash = \hash_hmac('sha256',
            \trim($route, '/') . '|' . \implode('#', $params),
            $this->secret,
            true
        );

        return $this->urlEncode($hash);
    }

    /**
     * This adds an HMAC to a list of query params.
     * If
     * @param array $queryParams List of query parameters
     * @param bool $allowAddition Whether to allow extra parameters to be added.
     * @throws \Exception
     * @return void
     */
    public function signParams(
        array &$queryParams,
        $allowAddition = true,
        ?\DateTimeInterface $expiration = null
    ): void {
        if (isset($queryParams[$this->hmacParam])) {
            throw new \RuntimeException("HMAC param is already present");
        }

        $route = $queryParams[0];

        if (\strncmp($route, '/', 1) !== 0) {
            throw new \RuntimeException("Route must be absolute (start with /)");
        }

        $this->addExpiration($queryParams, $expiration);
        if ($allowAddition) {
            $this->addParamKeys($queryParams);
        }

        $queryParams[$this->hmacParam] = $this->calculateHMAC($queryParams, $route);
    }

    /**
     * Adds the expiration param if needed.
     */
    private function addExpiration(array &$params, ?\DateTimeInterface $expiration = null): void
    {
        if (!empty($this->expirationParam)) {
            if (!isset($expiration)) {
                $expiration = (new \DateTime())->add($this->_defaultExpirationInterval);
            }
            $params[$this->expirationParam] = $expiration->getTimestamp();
        }
    }

    private function checkExpiration(array $params): bool
    {
        // Check expiration date.
        return $params[$this->expirationParam] > \time();
    }

    /**
     * Adds the keys of all params to the param array so it is included for signing.
     * @param array $params
     */
    private function addParamKeys(array &$params): void
    {
        $keys = \array_keys($params);
        if ($keys[0] === 0) {
            unset($keys[0]);
        }
        $params[$this->paramsParam] = \implode(',', $keys);
    }

    /**
     * Extracts the signed params from an array of params.
     * @param array $params
     * @return array
     */
    private function getSignedParams(array $params): array
    {
        if (empty($params[$this->paramsParam])) {
            // HMAC itself is never signed.
            unset($params[$this->hmacParam]);
            return $params;
        }

        $signedParams = [];
        $signedParams[$this->paramsParam] = $params[$this->paramsParam];

        foreach(\explode(',', $params[$this->paramsParam]) as $signedParam) {
            $signedParams[$signedParam] = $params[$signedParam] ?? null;
        }

        return $signedParams;
    }

    /**
     * Verifies the params for a specific route.
     * Checks that the HMAC is present and valid.
     * Checks that the HMAC is not expired.
     * @param array $params
     * @throws \Exception
     * @return bool
     */
    public function verify(array $params, string $route):bool
    {
        if (!isset($params[$this->hmacParam])) {
           return false;
        }
        $hmac = $params[$this->hmacParam];

        $signedParams = $this->getSignedParams($params);

        $calculated = $this->calculateHMAC($signedParams, $route);
        if (!\hash_equals($calculated, $hmac)) {
            return false;
        }

        return $this->checkExpiration($params);
    }

    private function urlEncode(string $bytes): string
    {
        return StringHelper::base64UrlEncode($bytes);
    }
}
