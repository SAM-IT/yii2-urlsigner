<?php

declare(strict_types=1);

use yii\web\IdentityInterface;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * @template TUserIdentity of IdentityInterface
 * @extends \yii\BaseYii<TUserIdentity>
 */
class Yii extends \yii\BaseYii
{
}

\Yii::$container = new \yii\di\Container();
