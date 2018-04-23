<?php

namespace EFrame\Auth\Http\Middleware;

use Closure;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class CheckIssuerMiddleware extends BaseMiddleware
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
        $params = func_get_args();

        $issuers = $this->getIssuers(...$params);

        $token = null;

        if ($this->auth->parser()->setRequest($request)->hasToken()) {

            $token = $this->auth;

        }

        throw_unless(
            $this->checkIssuer($token, $issuers),
            AccessDeniedHttpException::class
        );

        return $next($request);
    }

    /**
     * @param JWTAuth|null $token
     * @param array        $issuers
     *
     * @return bool
     */
    protected function checkIssuer(JWTAuth $token = null, array $issuers)
    {
        return (
            (
                null !== $token &&
                in_array($token->getClaim('iss'), $issuers)
            ) || (
                null === $token &&
                in_array('none', $issuers)
            ) || (
                count($issuers) === 0
            )
        );
    }

    /**
     * @param         $request
     * @param Closure $next
     *
     * @return array
     */
    protected function getIssuers($request, Closure $next)
    {
        $params = func_get_args();

        array_shift($params);
        array_shift($params);

        return $params;
    }
}
