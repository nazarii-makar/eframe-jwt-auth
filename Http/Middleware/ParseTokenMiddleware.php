<?php

namespace EFrame\JWTAuth\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class ParseTokenMiddleware extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if ($this->auth->parser()->setRequest($request)->hasToken()) {
            $this->auth->getToken();

            $this->auth->checkOrFail();
        }

        return $next($request);
    }
}
