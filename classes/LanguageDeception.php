<?php
/**
 * LanguageDeception.php
 * ============================================================
 * Applies to EVERY response — not just diverted honeypot ones.
 * Even a legitimate curl request to the site should reveal
 * the fake language, not PHP.
 *
 * Tools this defeats:
 *   WhatWeb       — reads Server, X-Powered-By, cookies, meta tags
 *   Wappalyzer    — reads headers, HTML meta/script/link, JS vars
 *   nikto         — reads headers, content, error pages
 *   whatweb       — same as WhatWeb
 *   BuiltWith     — reads script URLs, meta tags
 *   nmap -sV      — reads service banners
 *   curl -I       — reads response headers
 *   Burp passive  — reads every header and HTML comment
 *
 * What gets spoofed:
 *   1. HTTP headers          Server, X-Powered-By, X-Framework
 *   2. Session cookies       sessionid vs JSESSIONID vs connect.sid
 *   3. ETag format           Weak vs strong, PHP vs Node style
 *   4. HTML meta tags        <meta name="generator"> etc.
 *   5. HTML JS variables     window.csrfToken vs Cookies['csrftoken']
 *   6. HTML comments         <!-- Built with Django 4.2 -->
 *   7. Error page format     DRF JSON vs Spring JSON vs Rails HTML
 *   8. Response timing       Delayed to match the fake tech's speed
 *   9. PHP ini suppression   expose_php=off, display_errors=off
 *  10. URL pattern hints     Fake API version paths
 * ============================================================
 */

namespace Aegis\Classes;

class LanguageDeception
{
    // Wappalyzer pattern fingerprints per fake tech
    // These are injected into HTML <head> of non-API responses
    private const HTML_FINGERPRINTS = [
        'DJANGO' => [
            'meta_generator' => 'Django',
            'js_vars'        => "window.csrfToken = document.cookie.match(/csrftoken=([^;]+)/)?.[1] ?? '';",
            'html_comment'   => '<!-- Built with Django 4.2.7 / Python 3.11 -->',
            'link_tags'      => '<link rel="stylesheet" href="/static/css/styles.css">',
            'script_path'    => '/static/js/main.js',
        ],
        'SPRING_BOOT' => [
            'meta_generator' => 'Spring Boot 3.1.4',
            'js_vars'        => "var SPRING_SECURITY_CONTEXT = {};",
            'html_comment'   => '<!-- Thymeleaf Template Engine 3.1 / Spring Boot 3.1.4 -->',
            'link_tags'      => '<link rel="stylesheet" href="/webjars/bootstrap/css/bootstrap.min.css">',
            'script_path'    => '/webjars/jquery/jquery.min.js',
        ],
        'RAILS' => [
            'meta_generator' => 'Ruby on Rails 7.0',
            'js_vars'        => "var Rails = { csrfToken: function() { return document.querySelector('meta[name=csrf-token]').content; } };",
            'html_comment'   => '<!-- Ruby on Rails 7.0.8 -->',
            'link_tags'      => '<meta name="csrf-token" content="' . self::fakeCsrfToken() . '">',
            'script_path'    => '/assets/application.js',
        ],
        'NODEJS' => [
            'meta_generator' => 'Express.js',
            'js_vars'        => "window.__INITIAL_STATE__ = {}; window.NODE_ENV = 'production';",
            'html_comment'   => '<!-- Node.js/Express 4.18.2 -->',
            'link_tags'      => '<link rel="stylesheet" href="/public/css/styles.css">',
            'script_path'    => '/public/js/bundle.js',
        ],
        'ASPNET' => [
            'meta_generator' => 'ASP.NET Core 7.0',
            'js_vars'        => "var __RequestVerificationToken = '" . bin2hex(random_bytes(16)) . "';",
            'html_comment'   => '<!-- Microsoft ASP.NET Core / IIS -->',
            'link_tags'      => '<link rel="stylesheet" href="/_content/site.css">',
            'script_path'    => '/_framework/blazor.server.js',
        ],
        'GOLANG' => [
            'meta_generator' => 'Go/Gin',
            'js_vars'        => "const API_VERSION = 'v1'; const BUILD = 'go1.21.1';",
            'html_comment'   => '<!-- Gin Web Framework 1.9.1 / Go 1.21 -->',
            'link_tags'      => '<link rel="stylesheet" href="/static/css/app.css">',
            'script_path'    => '/static/js/app.js',
        ],
        'LARAVEL' => [
            'meta_generator' => 'Laravel 9.52',
            'js_vars'        => "window.Laravel = { csrfToken: '" . bin2hex(random_bytes(16)) . "' };",
            'html_comment'   => '<!-- Laravel 9.52 / PHP 7.4 -->',   // old PHP version
            'link_tags'      => '<link rel="stylesheet" href="/css/app.css">',
            'script_path'    => '/js/app.js',
        ],
    ];

    // ETag format per tech — fingerprinted by sophisticated scanners
    private const ETAG_FORMATS = [
        'DJANGO'      => fn() => '"' . md5(microtime()) . '"',                  // strong ETag
        'SPRING_BOOT' => fn() => 'W/"' . dechex(rand(100000, 999999)) . '"',   // weak ETag
        'RAILS'       => fn() => '"' . sha1(microtime()) . '"',                 // SHA1 strong
        'NODEJS'      => fn() => 'W/"' . base_convert(rand(), 10, 36) . '"',   // weak, base36
        'ASPNET'      => fn() => '"' . strtoupper(md5(microtime())) . '"',     // uppercase MD5
        'GOLANG'      => fn() => '"' . substr(hash('sha256', microtime()), 0, 16) . '"',
        'LARAVEL'     => fn() => '"' . md5(microtime()) . '"',
    ];

    // X-Runtime header (Rails adds this — microseconds)
    private const RUNTIME_HEADERS = [
        'RAILS'  => fn() => 'X-Runtime: ' . round(rand(10, 400) / 1000, 6),
        'DJANGO' => fn() => null,
        'NODEJS' => fn() => null,
    ];

    // ================================================================
    //  CORE PUBLIC METHODS
    // ================================================================

    /**
     * Apply ALL deception headers. Call this before any output on
     * every request — both real routes and diverted honeypot routes.
     *
     * @param int    $siteId    Used to consistently select the same fake tech
     * @param bool   $isHtml    True if the response is an HTML page (not JSON API)
     */
    public static function applyAll(int $siteId, bool $isHtml = false): void
    {
        // Suppress PHP's own fingerprinting headers immediately
        self::suppressPhpHeaders();

        // Get the consistently-selected fake tech for this site
        $stack = TechDeception::getStack($siteId);
        $key   = $stack['key'];

        // Apply HTTP headers
        self::applyHttpHeaders($stack);

        // Add ETag in the fake tech's format
        self::applyETag($key);

        // Add runtime header if the fake tech uses one
        self::applyRuntimeHeader($key);

        // Remove any headers that would leak PHP
        self::removeLeakHeaders();
    }

    /**
     * Returns a fake HTML <head> injection string for HTML responses.
     * Inject this inside <head> of any HTML page your app serves.
     *
     * Usage in your Blade/Twig template:
     *   {!! \Aegis\Classes\LanguageDeception::htmlHeadInjection($siteId) !!}
     */
    public static function htmlHeadInjection(int $siteId): string
    {
        $stack   = TechDeception::getStack($siteId);
        $key     = $stack['key'];
        $fp      = self::HTML_FINGERPRINTS[$key] ?? self::HTML_FINGERPRINTS['DJANGO'];

        $lines   = [];

        // meta generator — Wappalyzer reads this
        $lines[] = '<meta name="generator" content="' . htmlspecialchars($fp['meta_generator']) . '">';

        // CSRF / framework link tags
        $lines[] = $fp['link_tags'];

        // Inline JavaScript variables — Wappalyzer pattern-matches these
        $lines[] = '<script>';
        $lines[] = $fp['js_vars'];
        $lines[] = '</script>';

        // HTML comment — WhatWeb reads HTML comments
        $lines[] = $fp['html_comment'];

        // Script src — BuiltWith and Wappalyzer match script paths
        $lines[] = '<script src="' . $fp['script_path'] . '" defer></script>';

        return implode("\n", $lines);
    }

    /**
     * Returns a fake 404 HTML page formatted in the fake tech's style.
     * Use this instead of PHP's own 404 page on non-API routes.
     */
    public static function html404Page(int $siteId): string
    {
        $stack = TechDeception::getStack($siteId);
        $key   = $stack['key'];

        return match ($key) {
            'DJANGO' => self::django404(),
            'RAILS'  => self::rails404(),
            'NODEJS' => self::node404(),
            'ASPNET' => self::aspnet404(),
            default  => self::generic404($stack['framework'] ?? 'Framework'),
        };
    }

    /**
     * Returns a fake 500 error page in the fake tech's style.
     * An attacker who triggers a server error should see Django/Rails
     * tracebacks, not PHP's error output.
     */
    public static function html500Page(int $siteId, string $context = ''): string
    {
        $stack = TechDeception::getStack($siteId);
        $key   = $stack['key'];

        return match ($key) {
            'DJANGO'      => self::django500($context),
            'SPRING_BOOT' => self::springBoot500(),
            'RAILS'       => self::rails500(),
            'NODEJS'      => self::node500($context),
            default       => self::generic500($stack),
        };
    }

    /**
     * Returns the fake tech key currently assigned to a site.
     * Used by your real routes to know which tech to pretend to be.
     */
    public static function getFakeTechKey(int $siteId): string
    {
        $stack = TechDeception::getStack($siteId);
        return $stack['key'];
    }

    // ================================================================
    //  HEADER HELPERS
    // ================================================================

    private static function suppressPhpHeaders(): void
    {
        // Turn off PHP's own header injection
        @ini_set('expose_php',     'Off');
        @ini_set('display_errors', 'Off');

        // Remove headers PHP may have already sent
        header_remove('X-Powered-By');
        header_remove('Server');
    }

    private static function removeLeakHeaders(): void
    {
        // These headers reveal PHP or the real server version
        $leaky = ['X-Powered-By', 'Server', 'X-PHP-Version', 'PHP-Version'];
        foreach ($leaky as $h) {
            header_remove($h);
        }
    }

    private static function applyHttpHeaders(array $stack): void
    {
        header('Server: ' . ($stack['server'] ?? 'nginx/1.24.0'));

        if (!empty($stack['x_powered_by'])) {
            header('X-Powered-By: ' . $stack['x_powered_by']);
        }
        if (!empty($stack['x_framework'])) {
            header('X-Framework: ' . $stack['x_framework']);
        }

        // Security headers every serious framework sends
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Vary: Accept-Encoding, Accept');
        header('X-Request-ID: ' . bin2hex(random_bytes(8)));

        // CORS — matches what the fake tech would send
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, '
             . ($stack['csrf_header'] ?? 'X-CSRF-Token'));

        // Session cookie with the fake tech's name
        if (!empty($stack['session_cookie'])) {
            $fake = bin2hex(random_bytes(16));
            setcookie(
                $stack['session_cookie'],
                $fake,
                ['path' => '/', 'httponly' => true, 'samesite' => 'Lax']
            );
        }
    }

    private static function applyETag(string $key): void
    {
        $fn    = self::ETAG_FORMATS[$key] ?? self::ETAG_FORMATS['DJANGO'];
        header('ETag: ' . $fn());
    }

    private static function applyRuntimeHeader(string $key): void
    {
        $fn = self::RUNTIME_HEADERS[$key] ?? null;
        if ($fn) {
            $h = $fn();
            if ($h) header($h);
        }
    }

    private static function fakeCsrfToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    // ================================================================
    //  FAKE ERROR PAGES  (HTML, not JSON — for browser requests)
    // ================================================================

    private static function django404(): string
    {
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><title>Page not found</title>
<style>
body{font-family:Georgia,serif;color:#000;background:#fff;margin:0;padding:20px}
h1{border-bottom:1px solid #000;padding-bottom:10px;font-size:28px}
.info{background:#f8f8f8;padding:10px;border-left:5px solid #ccc;margin:20px 0}
</style></head>
<body>
<h1>Not Found</h1>
<p>The requested resource <strong>was not found</strong> on this server.</p>
<div class="info">
  <p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.
  Change that to <code>False</code>, and Django will display a standard 404 page.</p>
</div>
<p>Django Version: 4.2.7 | Python 3.11.4 | Time: {$_SERVER['REQUEST_TIME_FLOAT']}</p>
</body></html>
HTML;
    }

    private static function django500(string $context): string
    {
        $trace = htmlspecialchars($context ?: 'views.py');
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><title>Server Error (500)</title>
<style>body{font-family:monospace;background:#fff;padding:20px}
.traceback{background:#f8f8f8;border:1px solid #ccc;padding:10px;overflow:auto}
.exception{color:#c00;font-weight:bold}</style></head>
<body>
<h1 class="exception">Server Error</h1>
<p>There is a server error. Please contact the webmaster.</p>
<div class="traceback">
<pre>Traceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/django/core/handlers/exception.py", line 55, in inner
    response = get_response(request)
  File "/usr/local/lib/python3.11/site-packages/django/core/handlers/base.py", line 197, in _get_response
    response = wrapped_callback(request, *callback_args, **callback_kwargs)
  File "/opt/app/$trace", line 42, in index
    data = serializer.data
django.core.exceptions.OperationalError: no such table: app_user</pre>
</div>
<p>Django/4.2.7 Python/3.11.4</p>
</body></html>
HTML;
    }

    private static function rails404(): string
    {
        return <<<HTML
<!DOCTYPE html>
<html><head><title>The page you were looking for doesn't exist (404)</title>
<style>body{background:#fff;color:#666;font-family:Arial,Helvetica,sans-serif;font-size:small;margin:0;padding:0}
div.dialog{width:25em;margin:4em auto 0 auto;border:1px solid #ccc;padding:0}
h1{font-size:100%;background:#f0a9a9;color:#fff;padding:.5em;margin:0}</style></head>
<body>
<div class="dialog">
<h1>The page you were looking for doesn't exist.</h1>
<p>You may have mistyped the address or the page may have moved.</p>
<p>If you are the application owner check the logs for more information.</p>
</div>
</body></html>
HTML;
    }

    private static function node404(): string
    {
        http_response_code(404);
        header('Content-Type: application/json');
        return json_encode([
            'error'     => 'Not Found',
            'message'   => 'Cannot GET ' . htmlspecialchars($_SERVER['REQUEST_URI'] ?? '/'),
            'status'    => 404,
        ]);
    }

    private static function aspnet404(): string
    {
        return <<<HTML
<!DOCTYPE html>
<html><head><title>404 - File or directory not found.</title>
<style>body{margin:0;background:#fff;font-family:"Trebuchet MS",Verdana,sans-serif}
#header{background:#3c5977;padding:10px}
#header h1{color:#fff;margin:0}
#content{padding:20px}</style></head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
<h2>404 - File or directory not found.</h2>
<h3>The resource you are looking for might have been removed, had its name changed,
or is temporarily unavailable.</h3>
</div>
</body></html>
HTML;
    }

    private static function rails500(): string
    {
        return <<<HTML
<!DOCTYPE html>
<html><head><title>We're sorry, but something went wrong (500)</title>
<style>body{background:#fff;color:#666;font-family:Arial,Helvetica,sans-serif;font-size:small}
div.dialog{width:25em;margin:4em auto 0 auto;border:1px solid #ccc;padding:0}
h1{font-size:100%;background:#f0a9a9;color:#fff;padding:.5em;margin:0}</style></head>
<body>
<div class="dialog">
<h1>We're sorry, but something went wrong.</h1>
<p>If you are the application owner check the logs for more information.</p>
</div>
</body></html>
HTML;
    }

    private static function springBoot500(): string
    {
        http_response_code(500);
        header('Content-Type: application/json');
        return json_encode([
            'timestamp' => (new \DateTime())->format('Y-m-d\TH:i:s.v+0000'),
            'status'    => 500,
            'error'     => 'Internal Server Error',
            'message'   => '',
            'path'      => $_SERVER['REQUEST_URI'] ?? '/',
        ]);
    }

    private static function node500(string $context): string
    {
        http_response_code(500);
        header('Content-Type: application/json');
        return json_encode([
            'error'  => 'Internal Server Error',
            'message'=> $context ?: 'Something went wrong',
            'stack'  => "Error: Something went wrong\n    at /opt/app/src/app.js:42:15",
        ]);
    }

    private static function generic404(string $framework): string
    {
        return "<html><body><h1>404 Not Found</h1><p>Powered by {$framework}</p></body></html>";
    }

    private static function generic500(array $stack): string
    {
        return "<html><body><h1>500 Internal Server Error</h1>"
             . "<p>Server: " . htmlspecialchars($stack['server'] ?? 'nginx') . "</p></body></html>";
    }
}
