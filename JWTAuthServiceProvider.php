<?php

namespace EFrame\JWTAuth;

use EFrame\JWTAuth\Providers\JWT\Lcobucci;
use Lcobucci\JWT\Parser as JWTParser;
use Lcobucci\JWT\Builder as JWTBuilder;
use Illuminate\Support\ServiceProvider;

class JWTAuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('app.jwt.provider.jwt.lcobucci', Lcobucci::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerJWTProvider()
    {
        $this->registerLcobucciProvider();
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('app.jwt.provider.jwt.lcobucci', function ($app) {
            return new Lcobucci(
                new JWTBuilder(),
                new JWTParser(),
                config('jwt.secret'),
                config('jwt.algo'),
                config('jwt.keys')
            );
        });
    }
}
