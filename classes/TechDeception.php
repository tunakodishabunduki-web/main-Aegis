<?php
namespace Aegis\Classes;

class TechDeception
{
    private static array $selected = [];

    private const STACKS = [
        'DJANGO' => [
            'server'         => 'nginx/1.24.0',
            'x_powered_by'   => null,
            'x_framework'    => 'Django/4.2.7',
            'session_cookie' => 'sessionid',
            'csrf_header'    => 'X-CSRFToken',
            'token_format'   => 'Token %s',
            'timing_ms'      => [45, 280],
            'language'       => 'Python 3.11',
        ],
        'SPRING_BOOT' => [
            'server'         => 'Apache/2.4.57',
            'x_powered_by'   => null,
            'x_framework'    => 'Spring Boot/3.1.4',
            'session_cookie' => 'JSESSIONID',
            'csrf_header'    => 'X-XSRF-TOKEN',
            'token_format'   => 'Bearer %s',
            'timing_ms'      => [80, 450],
            'language'       => 'Java 17',
        ],
        'RAILS' => [
            'server'         => 'Puma/6.3.1',
            'x_powered_by'   => null,
            'x_framework'    => 'Ruby on Rails/7.0.8',
            'session_cookie' => '_session_id',
            'csrf_header'    => 'X-CSRF-Token',
            'token_format'   => 'Bearer %s',
            'timing_ms'      => [60, 350],
            'language'       => 'Ruby 3.2',
        ],
        'NODEJS' => [
            'server'         => 'nginx/1.22.1',
            'x_powered_by'   => 'Express',
            'x_framework'    => null,
            'session_cookie' => 'connect.sid',
            'csrf_header'    => 'X-CSRF-Token',
            'token_format'   => 'Bearer %s',
            'timing_ms'      => [20, 150],
            'language'       => 'Node.js 20',
        ],
        'ASPNET' => [
            'server'         => 'Microsoft-IIS/10.0',
            'x_powered_by'   => 'ASP.NET',
            'x_framework'    => 'ASP.NET Core/7.0.12',
            'session_cookie' => 'ASP.NET_SessionId',
            'csrf_header'    => 'RequestVerificationToken',
            'token_format'   => 'Bearer %s',
            'timing_ms'      => [70, 400],
            'language'       => 'C# 11',
        ],
        'GOLANG' => [
            'server'         => 'nginx/1.24.0',
            'x_powered_by'   => null,
            'x_framework'    => 'Gin/1.9.1',
            'session_cookie' => 'go_session',
            'csrf_header'    => 'X-CSRF-Token',
            'token_format'   => 'Bearer %s',
            'timing_ms'      => [5, 80],
            'language'       => 'Go 1.21',
        ],
        'LARAVEL' => [
            'server'         => 'Apache/2.4.54 (Ubuntu)',
            'x_powered_by'   => 'PHP/7.4.33',
            'x_framework'    => 'Laravel/9.52',
            'session_cookie' => 'laravel_session',
            'csrf_header'    => 'X-CSRF-TOKEN',
            'token_format'   => 'Bearer %s',
            'timing_ms'      => [90, 500],
            'language'       => 'PHP 7.4',
        ],
    ];

    private const TECH_MAP = [
        'PHP'    => ['DJANGO','SPRING_BOOT','RAILS','NODEJS','ASPNET','GOLANG'],
        'PYTHON' => ['SPRING_BOOT','ASPNET','NODEJS','GOLANG','LARAVEL'],
        'NODE'   => ['DJANGO','SPRING_BOOT','RAILS','ASPNET','GOLANG'],
        'JAVA'   => ['DJANGO','RAILS','NODEJS','GOLANG','ASPNET'],
        'RUBY'   => ['DJANGO','SPRING_BOOT','NODEJS','ASPNET','GOLANG'],
    ];

    private const ERRORS = [
        'DJANGO'      => [401 => ['detail'=>'Authentication credentials were not provided.','code'=>'not_authenticated'],
                          403 => ['detail'=>'You do not have permission to perform this action.','code'=>'permission_denied'],
                          404 => ['detail'=>'Not found.','code'=>'not_found'],
                          500 => ['detail'=>'A server error occurred.','code'=>'server_error']],
        'SPRING_BOOT' => [401 => ['status'=>401,'error'=>'Unauthorized','message'=>'Full authentication is required','path'=>null,'timestamp'=>null],
                          403 => ['status'=>403,'error'=>'Forbidden','message'=>'Access Denied','path'=>null,'timestamp'=>null],
                          404 => ['status'=>404,'error'=>'Not Found','message'=>'No message available','path'=>null,'timestamp'=>null],
                          500 => ['status'=>500,'error'=>'Internal Server Error','message'=>'','path'=>null,'timestamp'=>null]],
        'RAILS'       => [401 => ['error'=>'You need to sign in first.'],
                          403 => ['error'=>'You are not authorized to perform this action.'],
                          404 => ['error'=>"The page you were looking for doesn't exist."],
                          500 => ['error'=>"We're sorry, but something went wrong."]],
        'NODEJS'      => [401 => ['error'=>'Unauthorized','message'=>'No token provided','statusCode'=>401],
                          403 => ['error'=>'Forbidden','message'=>'Insufficient permissions','statusCode'=>403],
                          404 => ['error'=>'Not Found','message'=>'Resource not found','statusCode'=>404],
                          500 => ['error'=>'Internal Server Error','message'=>'An unexpected error occurred','statusCode'=>500]],
        'ASPNET'      => [401 => ['type'=>'https://httpstatuses.com/401','title'=>'Unauthorized.','status'=>401],
                          403 => ['type'=>'https://httpstatuses.com/403','title'=>'Access denied.','status'=>403],
                          404 => ['type'=>'https://httpstatuses.com/404','title'=>'Resource not found.','status'=>404],
                          500 => ['type'=>'https://httpstatuses.com/500','title'=>'An error occurred.','status'=>500]],
        'GOLANG'      => [401 => ['error'=>'unauthorized','code'=>401],
                          403 => ['error'=>'forbidden','code'=>403],
                          404 => ['error'=>'resource not found','code'=>404],
                          500 => ['error'=>'internal server error','code'=>500]],
        'LARAVEL'     => [401 => ['message'=>'Unauthenticated.'],
                          403 => ['message'=>'This action is unauthorized.'],
                          404 => ['message'=>'Not Found'],
                          500 => ['message'=>'Server Error']],
    ];

    public static function getStack(int $siteId, string $realTech = 'PHP'): array
    {
        if (isset(self::$selected[$siteId])) return self::$selected[$siteId];
        $options = self::TECH_MAP[strtoupper($realTech)] ?? self::TECH_MAP['PHP'];
        $r       = new \Random\Randomizer(new \Random\Engine\Mt19937($siteId + 42));
        $key     = $options[$r->getInt(0, count($options) - 1)];
        $stack   = array_merge(self::STACKS[$key], ['key' => $key]);
        self::$selected[$siteId] = $stack;
        return $stack;
    }

    public static function applyHeaders(int $siteId, string $path = '/'): void
    {
        $stack = self::getStack($siteId);
        header_remove('X-Powered-By');
        header_remove('Server');
        header('Server: ' . $stack['server']);
        if ($stack['x_powered_by']) header('X-Powered-By: ' . $stack['x_powered_by']);
        if ($stack['x_framework'])  header('X-Framework: ' . $stack['x_framework']);
        header('X-Content-Type-Options: nosniff');
        header('X-Request-ID: ' . bin2hex(random_bytes(8)));
        header('X-Response-Time: ' . rand($stack['timing_ms'][0], $stack['timing_ms'][1]) . 'ms');
        header('Vary: Accept-Encoding, Accept');
        if ($stack['session_cookie']) {
            $fake = bin2hex(random_bytes(16));
            header("Set-Cookie: {$stack['session_cookie']}={$fake}; Path=/; HttpOnly; SameSite=Lax", false);
        }
    }

    public static function errorResponse(int $siteId, int $httpCode, string $path = '/'): array
    {
        $stack  = self::getStack($siteId);
        $key    = $stack['key'];
        $errors = self::ERRORS[$key] ?? self::ERRORS['NODEJS'];
        $tpl    = $errors[$httpCode] ?? $errors[500];
        if ($key === 'SPRING_BOOT') {
            $tpl['timestamp'] = (new \DateTime())->format('Y-m-d\TH:i:s.v\Z');
            $tpl['path']      = $path;
        }
        return $tpl;
    }

    public static function loginSuccessResponse(int $siteId, array $fakeUser): array
    {
        $stack = self::getStack($siteId);
        $token = bin2hex(random_bytes(32));
        return match ($stack['key']) {
            'DJANGO'      => ['token' => $token, 'user' => $fakeUser],
            'SPRING_BOOT' => ['accessToken' => $token, 'tokenType' => 'Bearer', 'expiresIn' => 3600, 'user' => $fakeUser],
            'RAILS'       => ['auth_token' => $token, 'user' => $fakeUser],
            'ASPNET'      => ['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 3600, 'user' => $fakeUser],
            default       => ['success' => true, 'token' => $token, 'user' => $fakeUser],
        };
    }

    public static function csrfHeader(int $siteId): string
    {
        return self::getStack($siteId)['csrf_header'] ?? 'X-CSRF-Token';
    }
}
