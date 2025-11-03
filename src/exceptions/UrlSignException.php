<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner\exceptions;

/**
 * @method int<1, 2> getCode()
 */
final class UrlSignException extends \InvalidArgumentException
{
    public const int AlreadyPresent = 1;

    public const int RelativeRoute = 2;

    private function __construct(string $message, int $code)
    {
        parent::__construct($message, $code);
    }

    public static function AlreadyPresent(string $message = 'HMAC already present in params'): self
    {
        return new self($message, self::AlreadyPresent);
    }

    public static function RelativeRoute(string $message = 'Route cannot be relative'): self
    {
        return new self($message, self::RelativeRoute);
    }
}
