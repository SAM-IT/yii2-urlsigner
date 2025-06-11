<?php
declare(strict_types=1);
return [
    'class' => \yii\web\Application::class,
    'id' => 'yii2-phpfpm-test',
    'basePath' => __DIR__ . '/../src',
    'components' => [
        'i18n' => [
            'translations' => [
                'sam-it.urlsigner' => [
                    'class' => \yii\i18n\PhpMessageSource::class,
                    'fileMap' => [],
                ],
            ],
        ],
        'urlSigner' => SamIT\Yii2\UrlSigner\UrlSigner::class
    ]
];