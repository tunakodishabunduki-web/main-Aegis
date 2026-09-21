<?php
/**
 * aegis-bootstrap.php
 * ============================================================
 * The only file a protected site needs to include.
 * Drop this near the top of your index.php / bootstrap.php,
 * before any output and before your router runs.
 *
 * Minimum usage:
 *   define('AEGIS_INSTALL_KEY', 'hp_your_key_here');
 *   require_once __DIR__ . '/aegis/aegis-bootstrap.php';
 *
 * What it does in order:
 *   1. Suppresses PHP version disclosure globally (ini_set)
 *   2. Removes X-Powered-By and Server headers
 *   3. Applies language/tech-stack deception headers on every request
 *      — WhatWeb, Wappalyzer, curl -I all see the fake framework
 *   4. Detects scanner User-Agents and honeypot route hits
 *   5. Diverts confirmed attackers into the AI honeypot silently
 *   6. Logs every suspicious event to the central Aegis database
 *   7. Fires WhatsApp alerts and physical tracker on Critical events
 * ============================================================
 */

declare(strict_types=1);

// ── 1. Global PHP fingerprint suppression ──────────────────────
// These apply even before headers are sent, so ini_set works here.
@ini_set('expose_php',        'Off');   // removes PHP version from Server header
@ini_set('display_errors',    'Off');   // prevents PHP errors leaking to browser
@ini_set('log_errors',        'On');
@ini_set('session.name',      'id');    // session cookie name: 'id' instead of 'PHPSESSID'

// Remove headers PHP may add automatically
header_remove('X-Powered-By');

// ── 2. Autoloader ───────────────────────────────────────────────
$aegisDir = __DIR__;

// Support both Composer autoloading and manual class loading
if (file_exists($aegisDir . '/vendor/autoload.php')) {
    require_once $aegisDir . '/vendor/autoload.php';
} else {
    // Manual PSR-4-style loader (no Composer required)
    spl_autoload_register(function (string $class) use ($aegisDir): void {
        $map = [
            'Aegis\\Config\\'   => $aegisDir . '/config/',
            'Aegis\\Classes\\'  => $aegisDir . '/classes/',
            'Aegis\\Honeypot\\' => $aegisDir . '/honeypot/',
            'Aegis\\Bridge\\'   => $aegisDir . '/bridge/',
        ];
        foreach ($map as $prefix => $baseDir) {
            if (str_starts_with($class, $prefix)) {
                $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
                $file     = $baseDir . $relative . '.php';
                if (file_exists($file)) {
                    require_once $file;
                    return;
                }
            }
        }
    });
}

// ── 3. Environment variables (if .env file exists) ──────────────
$envFile = $aegisDir . '/.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with(trim($line), '#')) continue;
        if (str_contains($line, '=')) {
            [$key, $value] = explode('=', $line, 2);
            $key   = trim($key);
            $value = trim($value, " \t\"'");
            if (!getenv($key)) {
                putenv("{$key}={$value}");
                $_ENV[$key] = $value;
            }
        }
    }
}

// ── 4. Run the Aegis middleware ──────────────────────────────────
if (defined('AEGIS_INSTALL_KEY') && !empty(AEGIS_INSTALL_KEY)) {
    try {
        $aegis = new \Aegis\Honeypot\Middleware();
        $aegis->handle();
        // handle() calls exit on diverted requests.
        // If we reach this line, the request is legitimate — hand off.
    } catch (\Throwable $e) {
        // Never let Aegis break the real site.
        // Log silently and let the real app continue.
        error_log('[Aegis Bootstrap] Error: ' . $e->getMessage());
    }
}

// ── Your real app continues below this line ─────────────────────
