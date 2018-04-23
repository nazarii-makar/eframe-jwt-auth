<?php

namespace EFrame\Auth\Http\Middleware;

use Closure;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class IpGuardMiddleware
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

        $remotes = $this->getRemotes(...$params);

        throw_unless(
            $this->checkRemote($request->ip(), $remotes),
            AccessDeniedHttpException::class
        );

        return $next($request);
    }

    /**
     * @param       $remote
     * @param array $remotes
     *
     * @return bool
     */
    protected function checkRemote($remote, array $remotes)
    {
        return in_array($remote, $remotes);
    }

    /**
     * @param         $request
     * @param Closure $next
     *
     * @return array
     */
    protected function getRemotes($request, Closure $next)
    {
        $params = func_get_args();

        array_shift($params);
        array_shift($params);

        return $params;
    }
}
