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
    public const string  EXPIRES = 'expires';

    public const string  PARAMS = 'params';

    public const string HMAC = 'hmac';

    /**
     * Note that expiration dates cannot be disabled. If you really need to you can set a longer duration for the links.
     * @param \DateInterval $defaultExpirationInterval The default interval for link validity (default: 1 week)
     * Stores the current timestamp, primarily used for testing.
     */
    public function __construct(
        private ClockInterface $clock,
        #[SensitiveParameter]
        private string $secret,
        private DateInterval $defaultExpirationInterval = new \DateInterval('P7D'),
    ) {

    }

    /**
     * Calculates the HMAC for a URL.
     * @param array<mixed> $params
     **/
    private function calculateHMAC(
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
     * @return array{0: non-empty-string, self::EXPIRES: int, self::PARAMS?: string, self::HMAC: string}
     */
    public function sign(string $route, array $params, bool $allowAddition = true, null|\DateTimeInterface $expiration = null): array
    {
        if (isset($params[self::HMAC])) {
            throw UrlSignException::AlreadyPresent();
        }

        if (\strncmp($route, '/', 1) !== 0) {
            throw UrlSignException::RelativeRoute();
        }

        /**
         * @var array{0: string}
         */
        $result = $params;
        $result[0] = $route;

        $expiration ??= $this->clock->now()->add($this->defaultExpirationInterval);
        $result[self::EXPIRES] = $expiration->getTimestamp();
        if ($allowAddition) {
            $result[self::PARAMS] = $this->addParamKeys($result);
        };
        $result[self::HMAC] = $this->calculateHMAC($result, $route);
        return $result;
    }

    /**
     * @param array<mixed> $params
     */
    private function checkExpiration(array $params): void
    {
        // Check expiration date.
        if (isset($params[self::EXPIRES])
            && $params[self::EXPIRES] <= $this->clock->now()->getTimestamp()
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
        if (isset($params[0])) {
            unset($params[0]);
        }
        $keys = \array_keys($params);
        return \implode(',', $keys);
    }

    /**
     * Extracts the signed params from an array of params.
     * @param array<mixed> $params
     * @return array<mixed>
     */
    private function getSignedParams(array $params): array
    {
        $paramNames = $params[self::PARAMS] ?? null;

        if (empty($paramNames) || ! is_string($paramNames)) {
            // HMAC itself is never signed.
            unset($params[self::HMAC]);
            return $params;
        }

        $signedParams = [];
        $signedParams[self::PARAMS] = $paramNames;

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
        if (! isset($params[self::HMAC]) || ! is_string($params[self::HMAC])) {
            throw UrlVerificationException::MissingHMAC();
        }
        $hmac = $params[self::HMAC];

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
