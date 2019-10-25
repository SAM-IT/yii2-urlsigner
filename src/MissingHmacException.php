<?php
declare(strict_types=1);


namespace SamIT\Yii2\UrlSigner;


class MissingHmacException extends UrlSignerException
{
    public function __construct(int $code = 0, \Exception $previous = null)
    {
        parent::__construct('The security code for this URL is missing', $code, $previous);
    }
}