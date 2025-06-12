<?php

declare(strict_types=1);

namespace SamIT\Yii2\UrlSigner;

final class InvalidHmacException extends UrlSignerException
{
    public function __construct(int $code = 0, null|\Exception $previous = null)
    {
        parent::__construct(\Yii::t('sam-it.urlsigner', 'This security code in this URL invalid'), $code, $previous);
    }
}
