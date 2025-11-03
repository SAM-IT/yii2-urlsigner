<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner;

use DateInterval;
use DateTimeZone;
use InvalidArgumentException;
use Lcobucci\Clock\SystemClock;
use Psr\Clock\ClockInterface;
use SamIT\Yii2\UrlSigner\exceptions\UrlSignException;
use SamIT\Yii2\UrlSigner\exceptions\UrlVerificationException;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\web\ForbiddenHttpException;

class UrlSignerComponent extends Component
{
    /**
     * @var string The name of the URL param for the HMAC
     */
    public string $hmacParam = 'hmac' {
        set {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->hmacParam = $value;
        }
        get => $this->hmacParam;
    }

    /**
     * @var string The name of the URL param for the parameters
     */
    public string $paramsParam = 'params' {
        set {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->paramsParam = $value;
        }
        get => $this->paramsParam;
    }

    /**
     * @var string The name of the URL param for the expiration date time
     */
    public string $expirationParam = 'expires' {
        set {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->expirationParam = $value;
        }
        get => $this->expirationParam;
    }

    /**
     * Note that expiration dates cannot be disabled. If you really need to you can set a longer duration for the links.
     * @var \DateInterval The default interval for link validity (default: 1 week)
     */
    public DateInterval $defaultExpirationInterval {
        set(string|DateInterval $value) {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->defaultExpirationInterval = is_string($value) ? new DateInterval($value) : $value;
        }
        get => $this->defaultExpirationInterval ?? new DateInterval('P7D');
    }

    public string $secret {
        set {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->secret = $value;
        }
        get {
            if (! isset($this->secret)) {
                throw new InvalidConfigException('The secret must be set');
            }
            return $this->secret;
        }
    }

    public ClockInterface $clock {
        set {
            if ($this->locked) {
                throw new \RuntimeException('Cannot change params after the component has been initialized');
            }
            $this->clock = $value;
        }
        get {
            if (! isset($this->clock)) {
                if (! class_exists(SystemClock::class)) {
                    throw new InvalidConfigException('Either install lcobucci/clock or provide a clock implementation in the configuration');
                }
                $this->clock = new SystemClock(new DateTimeZone('UTC'));
            };
            return $this->clock;
        }
    }

    private UrlSigner $signer;

    private bool $locked = false;

    public function init(): void
    {
        parent::init();
        if (empty($this->secret)
            || empty($this->hmacParam)
            || empty($this->paramsParam)
            || empty($this->expirationParam)
        ) {
            throw new InvalidConfigException('The following configuration params are required: secret, hmacParam, paramsParam and expirationParam');
        }

        $this->signer = new UrlSigner(
            $this->clock,
            $this->secret,
            $this->hmacParam,
            $this->paramsParam,
            $this->expirationParam,
            $this->defaultExpirationInterval
        );
        $this->locked = true;
    }

    /**
     * @param non-empty-string $route
     * @param array<string, mixed> $params
     * @return array<string|0, mixed>
     */
    public function sign(string $route, array $params, bool $allowAddition = true, null|\DateTimeInterface $expiration = null): array
    {
        try {
            return $this->signer->sign($route, $params, $allowAddition, $expiration);
        } catch (UrlSignException $e) {
            $message = match ($e->getCode()) {
                UrlSignException::AlreadyPresent => \Yii::t('sam-it.urlsigner', "HMAC param is already present"),
                UrlSignException::RelativeRoute => \Yii::t('sam-it.urlsigner', "Route must be absolute (start with /)"),
            };
            throw new InvalidArgumentException($message, $e->getCode(), $e);
        }
    }

    /**
     * Verifies the params for a specific route.
     * Checks that the HMAC is present and valid.
     * Checks that the HMAC is not expired.
     * @param array<mixed> $params
     * @throws ForbiddenHttpException
     */
    public function verify(array $params, string $route): void
    {
        try {
            $this->signer->verify($params, $route);
        } catch (UrlVerificationException $e) {
            $message = match ($e->getCode()) {
                UrlVerificationException::ExpiredLink => \Yii::t('sam-it.urlsigner', 'This URL has expired'),
                UrlVerificationException::InvalidHmac => \Yii::t('sam-it.urlsigner', 'This security code in this URL invalid'),
                UrlVerificationException::MissingHmac => \Yii::t('sam-it.urlsigner', 'The security code for this URL is missing'),
            };
            throw new ForbiddenHttpException($message, $e->getCode(), $e);
        }
    }
}
