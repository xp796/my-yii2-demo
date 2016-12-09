<?php
return [
    'vendorPath' => dirname(dirname(__DIR__)) . '/vendor',
    'on beforeRequest'=>function($event){
        $locate = Yii::$app->request->cookies->get('locate');
        $language = isset($locate->value)?$locate->value:'en-US';
        Yii::$app->sourceLanguage = 'en-US';
        Yii::$app->language = $language;
        return;
    },
    'components' => [
        'cache' => [
            'class' => 'yii\caching\FileCache',
        ],
        'i18n'=>[
            'translations' => [
                'app*'=> [
                    'class' => 'yii\i18n\PhpMessageSource',
                    'basePath'=>'@common/messages',
                    'fileMap'=>[
                        'app'=>'app.php',
                    ],
                ],
            ],
        ],
    ],
];
