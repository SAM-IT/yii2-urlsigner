<?php
declare(strict_types=1);


namespace SamIT\Yii2\UrlSigner;


class ExpiredLinkException extends UrlSignerException
{
    public function __construct(int $code = 0, \Exception $previous = null)
    {
        parent::__construct(\Yii::t('sam-it.urlsigner', 'This URL has expired'), $code, $previous);
    }
}