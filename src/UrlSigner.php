<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner;

use DateInterval;
use yii\base\Component;
use yii\base\InvalidConfigException;

class UrlSigner extends Component
{
    /**
     * @var string The name of the URL param for the HMAC
     */
    public string $hmacParam = 'hmac';

    /**
     * @var string The name of the URL param for the parameters
     */
    public string $paramsParam = 'params';

    /**
     * @var null|string The name of the URL param for the expiration date time
     */
    public null|string $expirationParam = 'expires';

    /**
     * Note that expiration dates cannot be disabled. If you really need to you can set a longer duration for the links.
     * @var \DateInterval The default interval for link validity (default: 1 week)
     */
    private DateInterval $_defaultExpirationInterval;

    /**
     * Stores the current timestamp, primarily used for testing.
     */
    private null|int $_currentTimestamp;

    public string $secret;

    public function init(): void
    {
        parent::init();
        if (! isset($this->_defaultExpirationInterval)) {
            $this->setDefaultExpirationInterval('P7D');
        }
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

    public function setCurrentTimestamp(?int $time): void
    {
        $this->_currentTimestamp = $time;
    }

    /**
     * Calculates the HMAC for a URL.
     * @param array<mixed> $params
     **/
    public function calculateHMAC(
        array $params,
        string $route
    ): string {
        if (isset($params[0])) {
            unset($params[0]);
        }

        \ksort($params);

        $hash = \hash_hmac(
            'sha256',
            \trim($route, '/') . '|' . \implode('#', $params),
            $this->secret,
            true
        );

        return $this->urlEncode($hash);
    }

    /**
     * @param array<string, mixed> $params
     * @return array<string|0, mixed>
     */
    public function sign(string $route, array $params, bool $allowAddition = true, null|\DateTimeInterface $expiration = null): array
    {
        if (isset($params[$this->hmacParam])) {
            throw new \RuntimeException(\Yii::t('sam-it.urlsigner', "HMAC param is already present"));
        }

        if (\strncmp($route, '/', 1) !== 0) {
            throw new \RuntimeException(\Yii::t('sam-it.urlsigner', "Route must be absolute (start with /)"));
        }

        $result = [
            $route,
            ...$params,
            ...$this->addExpiration($expiration)
        ];
        if (isset($this->expirationParam)) {
            $expiration ??= (new \DateTime('@' . $this->time()))->add($this->_defaultExpirationInterval);
            $result[$this->expirationParam] = $expiration->getTimestamp();
        }
        if ($allowAddition) {
            $result[$this->paramsParam] = $this->addParamKeys($result);
        };
        $result[$this->hmacParam] = $this->calculateHMAC($result, $route);
        return $result;
    }

    /**
     * This adds an HMAC to a list of query params.
     * @param array<0|string, mixed> $queryParams List of query parameters
     * @param-out array<0|string, mixed> $queryParams
     * @param bool $allowAddition Whether to allow extra parameters to be added.
     * @throws \Exception
     * @deprecated Use ->sign instead
     */
    public function signParams(
        array &$queryParams,
        bool $allowAddition = true,
        ?\DateTimeInterface $expiration = null
    ): void {
        $route = $queryParams[0];
        if (! is_string($route)) {
            throw new \InvalidArgumentException(\Yii::t('sam-it.urlsigner', "Route must be a string"));
        }
        unset($queryParams[0]);
        $newParams = $this->sign($route, $queryParams, $allowAddition, $expiration);
        $queryParams = $newParams;
    }

    /**
     * Adds the expiration param if needed.
     * @return array<string, int>
     */
    private function addExpiration(?\DateTimeInterface $expiration = null): array
    {
        if (! empty($this->expirationParam)) {
            $expiration ??= (new \DateTime('@' . $this->time()))->add($this->_defaultExpirationInterval);
            return [$this->expirationParam => $expiration->getTimestamp()];
        }
        return [];
    }

    private function time(): int
    {
        return $this->_currentTimestamp ?? \time();
    }

    /**
     * @param array<mixed> $params
     */
    private function checkExpiration(array $params): void
    {
        // Check expiration date.
        if (isset($params[$this->expirationParam])
            && $params[$this->expirationParam] <= $this->time()
        ) {
            throw new ExpiredLinkException();
        }
    }

    /**
     * Adds the keys of all params to the param array so it is included for signing.
     * @param array<mixed> $params
     */
    private function addParamKeys(array $params): string
    {
        $keys = \array_keys($params);
        if ($keys[0] === 0) {
            unset($keys[0]);
        }
        return \implode(',', $keys);
    }

    /**
     * Extracts the signed params from an array of params.
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    private function getSignedParams(array $params): array
    {
        $paramNames = $params[$this->paramsParam] ?? null;

        if (empty($paramNames) || ! is_string($paramNames)) {
            // HMAC itself is never signed.
            unset($params[$this->hmacParam]);
            return $params;
        }

        $signedParams = [];
        $signedParams[$this->paramsParam] = $paramNames;

        foreach (\explode(',', $paramNames) as $signedParam) {
            $signedParams[$signedParam] = $params[$signedParam] ?? null;
        }

        return $signedParams;
    }

    /**
     * Verifies the params for a specific route.
     * Checks that the HMAC is present and valid.
     * Checks that the HMAC is not expired.
     * @param array<mixed> $params
     */
    public function verify(array $params, string $route): void
    {
        if (! isset($params[$this->hmacParam]) || ! is_string($params[$this->hmacParam])) {
            throw new MissingHmacException();
        }
        $hmac = $params[$this->hmacParam];

        $signedParams = $this->getSignedParams($params);

        $calculated = $this->calculateHMAC($signedParams, $route);
        if (! \hash_equals($calculated, $hmac)) {
            throw new InvalidHmacException();
        }

        $this->checkExpiration($params);
    }

    private function urlEncode(string $bytes): string
    {
        return strtr(base64_encode($bytes), '+/', '-_');
    }
}
