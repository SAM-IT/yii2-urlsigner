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
     * @var string The default interval for link validity (default: 1 week)
     */
    public $defaultExpirationInterval = 'P7D';

    /**
     * @var string
     */
    public $secret;

    public function init(): void
    {
        parent::init();
        if (!isset($this->secret)) {
            throw new InvalidConfigException('Secret is a required configration param');
        }
    }

    /**
     * Calculates the HMAC for a URL.
     * @param array $params A Yii2 route array, the first element is the route the rest are params.
     * @throws \Exception
     * @return string The HMAC
     */
    public function calculateHMAC(
        array $params,
        string $route
    ): string {
        if (isset($params[0])) {
            unset($params[0]);
        }

        \ksort($params);
        return \substr(\hash_hmac('sha256', \trim($route, '/') . '|' .  \implode('#', $params), $this->secret), 1, 16);
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

        $params = \array_keys($queryParams);
        $route = $queryParams[0];

        if (\strncmp($route, '/', 1) !== 0) {
            throw new \RuntimeException("Route must be absolute (start with /)");
        }


        if ($params[0] === 0) {
            unset($params[0]);
        }

        if (!isset($expiration)) {
            $expiration = (new \DateTime())->add(new \DateInterval($this->defaultExpirationInterval));
        }

        if (!empty($this->expirationParam)) {
            $queryParams[$this->expirationParam] = $expiration->getTimestamp();
            $params[] = $this->expirationParam;
        }

        \sort($params);
        if ($allowAddition) {
            $queryParams[$this->paramsParam] = \strtr(StringHelper::base64UrlEncode(\implode(',', $params)), ['=' => '']);
        }

        $queryParams[$this->hmacParam] = $this->calculateHMAC($queryParams, $route);
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
        $signedParams = [];
        if (!empty($params[$this->paramsParam])) {
            $signedParams[$this->paramsParam] = $params[$this->paramsParam];
            foreach(\explode(',', \base64_decode($params[$this->paramsParam], true)) as $signedParam) {
                $signedParams[$signedParam] = $params[$signedParam] ?? null;
            }
        } else {
            $signedParams = $params;
            unset($signedParams[$this->hmacParam]);
        }
        $calculated = $this->calculateHMAC($signedParams, $route);
        if (!\hash_equals($calculated, $hmac)) {
            return false;
        }

        // Check expiration date.
        return $signedParams[$this->expirationParam] > \time();
    }
}
