<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner\exceptions;

/**
 * @internal
 * @method int<1, 3> getCode()
 */
final class UrlVerificationException extends \RuntimeException
{
    public const int ExpiredLink = 1;

    public const int InvalidHmac = 2;

    public const int MissingHmac = 3;

    private function __construct(string $message, int $code)
    {
        parent::__construct($message, $code);
    }

    public static function ExpiredLink(): self
    {
        return new self('This URL has expired', self::ExpiredLink);
    }

    public static function InvalidHMAC(): self
    {
        return new self('Invalid HMAC', self::InvalidHmac);
    }

    public static function MissingHMAC(): self
    {
        return new self('Missing HMAC', self::MissingHmac);
    }
}
