<?php
declare(strict_types=1);


namespace SamIT\Yii2\UrlSigner;


use yii\web\ForbiddenHttpException;

abstract class UrlSignerException extends ForbiddenHttpException
{
}