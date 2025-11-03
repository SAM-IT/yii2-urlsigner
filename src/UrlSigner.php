<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner;

use DateInterval;
use Psr\Clock\ClockInterface;
use SamIT\Yii2\UrlSigner\exceptions\UrlSignException;
use SamIT\Yii2\UrlSigner\exceptions\UrlVerificationException;
use SensitiveParameter;

final readonly class UrlSigner
{
    /**
     * @param string $hmacParam The name of the URL param for the HMAC
     * @param string $paramsParam name of the URL param for the parameters
     * @param string $expirationParam The name of the URL param for the expiration date time
     * Note that expiration dates cannot be disabled. If you really need to you can set a longer duration for the links.
     * @param \DateInterval $defaultExpirationInterval The default interval for link validity (default: 1 week)
     * Stores the current timestamp, primarily used for testing.
     */
    public function __construct(
        private ClockInterface $clock,
        #[SensitiveParameter]
        private string $secret,
        private string $hmacParam = 'hmac',
        private string $paramsParam = 'params',
        private string $expirationParam = 'expires',
        private DateInterval $defaultExpirationInterval = new \DateInterval('P7D'),
    ) {

    }

    /**
     * Calculates the HMAC for a URL.
     * @param array<mixed> $params
     * @deprecated
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
     * @param non-empty-string $route
     * @param array<string, mixed> $params
     * @return array<string|0, mixed>
     */
    public function sign(string $route, array $params, bool $allowAddition = true, null|\DateTimeInterface $expiration = null): array
    {
        if (isset($params[$this->hmacParam])) {
            throw UrlSignException::AlreadyPresent();
        }

        if (\strncmp($route, '/', 1) !== 0) {
            throw UrlSignException::RelativeRoute();
        }

        $result = [
            $route,
            ...$params,
        ];

        $expiration ??= $this->clock->now()->add($this->defaultExpirationInterval);
        $result[$this->expirationParam] = $expiration->getTimestamp();

        if ($allowAddition) {
            $result[$this->paramsParam] = $this->addParamKeys($result);
        };
        $result[$this->hmacParam] = $this->calculateHMAC($result, $route);
        return $result;
    }

    /**
     * @param array<mixed> $params
     */
    private function checkExpiration(array $params): void
    {
        // Check expiration date.
        if (isset($params[$this->expirationParam])
            && $params[$this->expirationParam] <= $this->clock->now()->getTimestamp()
        ) {
            throw UrlVerificationException::ExpiredLink();
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
            throw UrlVerificationException::MissingHMAC();
        }
        $hmac = $params[$this->hmacParam];

        $signedParams = $this->getSignedParams($params);

        $calculated = $this->calculateHMAC($signedParams, $route);
        if (! \hash_equals($calculated, $hmac)) {
            throw UrlVerificationException::InvalidHMAC();
        }

        $this->checkExpiration($params);
    }

    private function urlEncode(string $bytes): string
    {
        return strtr(base64_encode($bytes), '+/', '-_');
    }
}
