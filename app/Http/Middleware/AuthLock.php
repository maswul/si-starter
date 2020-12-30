<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AuthLock
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {

        if(!$request->user()){
            return $next($request);
        }
        if ($request->user()->role < 3)
        {
            if (session('lock-expires-at')) {
                session()->forget('lock-expires-at');
            }

            return $next($request);
        }

        if ($lockExpiresAt = session('lock-expires-at')) {
            if ($lockExpiresAt < now() && url()->current() != route('login.locked')) {
                return redirect()->route('login.locked');
            }
        }

        session(['lock-expires-at' => now()->addMinutes(1)]); //15 minutes to lockOut
        session(['last_url' => url()->current()]);

        return $next($request);

    }
}
