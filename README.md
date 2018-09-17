[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/SAM-IT/yii2-urlsigner/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/SAM-IT/yii2-urlsigner/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/SAM-IT/yii2-urlsigner/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/SAM-IT/yii2-urlsigner/?branch=master)
[![Build Status](https://travis-ci.org/SAM-IT/yii2-urlsigner.svg?branch=master)](https://travis-ci.org/SAM-IT/yii2-urlsigner)

# yii2-urlsigner Secure URL signing and validation.

The goal of this component is to enable stateless but secure URL validation.
This can be useful, for example, when doing email validation or password reset.

The idea is simple, consider I want to change my email, the system could send me a link like this:
- http://myserver.example/newemail?user_id=1&email=newemail@fakemail.example

Of course, this is very insecure, and no one actually (hopefully) does it like this. One solution is to generate a random token:
- http://myserver.example/newemail?token=afjffepfggpkweggwg

This is secure, but requires keeping state on the server.
This package solves the problem by signing the URL.

- http://myserver.example/newemail?user_id=1&email=newemail@fakemail.example&hmac=fffwejggweorwiejfewoijwf

This allows us to verify that the URL was actually created by us therefore can be trusted.

# Example

```php

class RequestResetAction {

    public function run(
        UrlSigner $urlSigner,
        int $id,
        string $email
    ) {
        $user = User::find()->andWhere([
            'id' => $id,
            'email' => $email
        ]);

        $route = [
            '/user/do-reset',
            'id' => $user->id,
            'crc' => crc32($user->password_hash),
        ];

        /**
         * Sign the params.
         * 1st param is passed by reference, the component adds the params needed for HMAC.
         * 2nd param indicates that the params must match exactly, the user cannot add another param.
         * 3rd param sets the expiration to 1 hour
         **/
        $urlSigner->signParams($route, false, (new DateTime())->add(new DateInterval('PT1H')));

        $user->sendPasswordReset($route);



    }
}

class DoResetAction {

    public function behaviors()
    {
        return [
            'hmacFilter' => [
            'class' => HmacFilter::class,
            'signer' => $this->controller->module->get('urlSigner'),
        ];

    }
    public function run(
        int $id
    ) {
        // Here we can trust that the user got here through the link that we sent.



    }
}

```

# Do not share secrets across hosts
If you use this component in a multi-host application you must make sure each host uses a different secret.
The URL signing takes into account the absolute route and all given parameters, anything else is excluded from the signature and from validation.
This means that if you have a structure like this:
- https://users.app.com/
- https://admins.app.com/

And they use the same route, for example `/user/do-reset`, for password resets, a normal user will be able to change the domain without invalidating the signature.
