<?php
/**
 * SiteManager.php
 * Handles site registration, install-key generation, and aggregate
 * site statistics for the dashboard landing screen.
 */

namespace Aegis\Classes;

use Aegis\Config\Database;

class SiteManager
{
    private Database $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    /**
     * Registers a new site and returns its row including the install key.
     * Registering a URL alone does nothing — the site must have the
     * Aegis middleware installed on its own server before data flows in.
     */
    public function registerSite(string $siteUrl, string $siteName = ''): array
    {
        $installKey = $this->generateInstallKey();
        $siteName   = $siteName ?: parse_url($siteUrl, PHP_URL_HOST) ?: $siteUrl;

        $id = $this->db->insert(
            'INSERT INTO sites (site_url, site_name, install_key) VALUES (?, ?, ?)',
            [$siteUrl, $siteName, $installKey]
        );

        return [
            'id'          => (int) $id,
            'site_url'    => $siteUrl,
            'site_name'   => $siteName,
            'install_key' => $installKey,
            'snippet'     => $this->buildSnippet($installKey),
        ];
    }

    /**
     * Resolves a site by its install key header.
     * Returns null if not found.
     */
    public function resolveByKey(string $installKey): ?array
    {
        return $this->db->fetchOne(
            'SELECT id, site_url, site_name, owner_verified FROM sites WHERE install_key = ?',
            [$installKey]
        );
    }

    /**
     * Returns all registered sites with aggregate attack stats.
     */
    public function listSites(): array
    {
        return $this->db->fetchAll(
            'SELECT s.id, s.site_url, s.site_name, s.owner_verified,
                    s.created_at, s.last_report_at,
                    COUNT(DISTINCT ap.session_key) AS attacker_count,
                    COUNT(al.id)                   AS total_events,
                    COALESCE(MAX(al.severity_score), 0) AS max_severity,
                    SUM(CASE WHEN ap.is_banned = 1 THEN 1 ELSE 0 END) AS banned_count
             FROM sites s
             LEFT JOIN attacker_profile ap ON ap.site_id = s.id
             LEFT JOIN attack_log al       ON al.site_id = s.id
             GROUP BY s.id
             ORDER BY s.created_at DESC'
        );
    }

    /**
     * Returns one site's install snippet.
     */
    public function getSnippet(int $siteId): ?string
    {
        $row = $this->db->fetchOne('SELECT install_key FROM sites WHERE id = ?', [$siteId]);
        return $row ? $this->buildSnippet($row['install_key']) : null;
    }

    /**
     * Generates a cryptographically secure install key.
     */
    private function generateInstallKey(): string
    {
        return 'hp_' . bin2hex(random_bytes(24));
    }

    /**
     * Builds the PHP snippet to drop into the protected site.
     */
    private function buildSnippet(string $installKey): string
    {
        return <<<PHP
<?php
// 1. Copy the aegis/ folder into your project.
// 2. Install dependencies: composer require fpdf/fpdf
// 3. Add these lines near the TOP of your app's index.php / bootstrap:

define('AEGIS_INSTALL_KEY', '{$installKey}');
require_once __DIR__ . '/aegis/honeypot/Middleware.php';

use Aegis\Honeypot\Middleware;
\$middleware = new Middleware();
\$middleware->handle();       // runs before your real routes

// Your real routes continue below this line.
PHP;
    }
}
