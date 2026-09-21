<?php
/**
 * aegis/honeypot/RemoteReporter.php
 * ------------------------------------------------------------
 * Use this instead of Middleware.php when the site being
 * protected CANNOT share the same MySQL database as the
 * central Aegis dashboard (e.g. a client on a different host).
 *
 * Instead of writing directly to MySQL, it POSTs events to
 * the Aegis central API endpoint over HTTPS.
 *
 * Install on the remote site:
 *
 *   define('AEGIS_INSTALL_KEY', 'hp_...');
 *   define('AEGIS_CENTRAL_URL', 'https://simap.growthhub.co.tz/aegis');
 *   require_once __DIR__ . '/aegis/honeypot/RemoteReporter.php';
 *   (new \Aegis\Honeypot\RemoteReporter())->handle();
 */

namespace Aegis\Honeypot;

class RemoteReporter
{
    private string $installKey;
    private string $centralUrl;
    private int    $timeout = 3; // keep low so a slow Aegis doesn't slow the real site

    private const HONEYPOT_PATHS = [
        '/admin-legacy', '/api/v1/admin', '/wp-admin',
        '/api/config', '/.env', '/api/backup', '/phpmyadmin',
    ];

    private const SQLI  = "/('|\")\\s*(OR|AND)\\s*('|\")?\\s*=|UNION\\s+SELECT|DROP\\s+TABLE|--|;--/i";
    private const XSS   = '/<script|onerror\s*=|javascript:/i';
    private const PATH  = '/(\.\.[\/\\\\]|%2e%2e%2f|\/etc\/passwd)/i';
    private const SCAN  = '/sqlmap|nikto|nmap|burpsuite|hydra/i';

    public function __construct()
    {
        $this->installKey = defined('AEGIS_INSTALL_KEY') ? AEGIS_INSTALL_KEY : '';
        $this->centralUrl = defined('AEGIS_CENTRAL_URL') ? rtrim(AEGIS_CENTRAL_URL, '/') : '';
    }

    public function handle(): void
    {
        if (!$this->installKey || !$this->centralUrl) return;

        $path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $ua     = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip     = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '')[0]);

        // 1. Scanner UA
        if (preg_match(self::SCAN, $ua)) {
            $this->report('SCANNER_TOOL_DETECTED', $ip, $ua, $path, null, null, null);
        }

        // 2. Honeypot routes
        if (in_array($path, self::HONEYPOT_PATHS, true)) {
            $banned = $this->report('HONEYPOT_ROUTE_HIT', $ip, $ua, $path, null, null, null);
            http_response_code(404);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Not found']);
            exit;
        }

        // 3. Login inspection
        if (str_ends_with($path, '/login') || $path === '/api/login') {
            $body     = json_decode(file_get_contents('php://input') ?: '{}', true) ?? [];
            $username = $body['username'] ?? $_POST['username'] ?? null;
            $password = $body['password'] ?? $_POST['password'] ?? null;
            $combined = ($username ?? '') . ' ' . ($password ?? '');

            $type = null;
            if (preg_match(self::SQLI, $combined)) $type = 'SQL_INJECTION_ATTEMPT';
            elseif (preg_match(self::XSS,  $combined)) $type = 'XSS_ATTEMPT';
            elseif (preg_match(self::PATH, $combined)) $type = 'PATH_TRAVERSAL_ATTEMPT';

            if ($type) {
                $this->report($type, $ip, $ua, $path, $username, $password, null);
                http_response_code(401);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Invalid credentials']);
                exit;
            }
        }

        // 4. Delete trap
        if ($method === 'DELETE' && preg_match('#/admin/users/(\d+)#', $path, $m)) {
            $result = $this->report('DECOY_USER_DELETE_ATTEMPT', $ip, $ua, $path, null, null, null);
            if ($result && !empty($result['is_decoy'])) {
                http_response_code(403);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Session terminated']);
                exit;
            }
        }
    }

    /**
     * POSTs one event to the central Aegis API.
     * Returns the API response array, or null on failure.
     * Uses a short timeout so a slow central server never
     * blocks the real site's response to the end user.
     */
    private function report(
        string  $attackType,
        string  $ip,
        string  $ua,
        string  $path,
        ?string $username,
        ?string $password,
        ?array  $payload
    ): ?array {
        $data = json_encode([
            'attack_type'      => $attackType,
            'ip_address'       => $ip,
            'user_agent'       => $ua,
            'endpoint'         => $path,
            'entered_username' => $username,
            'entered_password' => $password,
            'payload'          => $payload,
        ]);

        $ch = curl_init($this->centralUrl . '/admin/api/ingest.php');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $data,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'X-Honeypot-Key: ' . $this->installKey,
            ],
        ]);

        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code === 200 && $body) {
            return json_decode($body, true);
        }
        return null;
    }
}
