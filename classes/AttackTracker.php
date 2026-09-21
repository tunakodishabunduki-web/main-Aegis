<?php
/**
 * AttackTracker.php
 * Fingerprints visitors, logs events to attack_log, maintains attacker_profile,
 * and decides when to ban. All operations are scoped to a site_id.
 */

namespace Aegis\Classes;

use Aegis\Config\Database;

class AttackTracker
{
    private Database $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    /**
     * Extracts IP, browser, OS, and a stable session fingerprint from
     * $_SERVER globals. No random salt — fingerprint must stay stable
     * across requests to group one attacker's actions together.
     */
    public function getClientDetails(): array
    {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR']
            ?? $_SERVER['REMOTE_ADDR']
            ?? 'unknown';
        $ip = trim(explode(',', $ip)[0]);

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

        preg_match('/(Windows NT [\d.]+|Mac OS X [\d_]+|Android [\d.]+|iPhone OS [\d_]+|Linux)/i', $ua, $osMatch);
        preg_match('/(Chrome|Firefox|Safari|Edge|OPR|Opera)\/([\d.]+)/i', $ua, $browserMatch);

        $sessionKey = substr(hash('sha256', $ip . '|' . $ua), 0, 32);

        return [
            'session_key' => $sessionKey,
            'ip'          => $ip,
            'user_agent'  => $ua,
            'os'          => $osMatch[1]    ?? 'Unknown',
            'browser'     => $browserMatch[1] ?? 'Unknown',
        ];
    }

    /**
     * Logs one suspicious event and upserts the attacker's profile.
     * Returns ['severity' => int, 'is_banned' => bool, 'session_key' => string].
     */
    public function logEvent(
        int     $siteId,
        string  $attackType,
        ?string $enteredUsername = null,
        ?string $enteredPassword = null,
        ?string $endpoint        = null,
        mixed   $payload         = null
    ): array {
        $client = $this->getClientDetails();
        $sessionKey = $client['session_key'];

        // Prior events for this session on this site (last 20)
        $priorEvents = $this->db->fetchAll(
            'SELECT attack_type FROM attack_log
             WHERE site_id = ? AND session_key = ?
             ORDER BY created_at DESC LIMIT 20',
            [$siteId, $sessionKey]
        );

        $severity = AttackScoring::scoreSession($priorEvents, $attackType);

        // Insert event
        $this->db->query(
            'INSERT INTO attack_log
             (site_id, session_key, ip_address, user_agent, browser, os, attack_type,
              entered_username, entered_password, endpoint, payload, severity_score)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $siteId,
                $sessionKey,
                $client['ip'],
                $client['user_agent'],
                $client['browser'],
                $client['os'],
                $attackType,
                $enteredUsername,
                $enteredPassword,
                $endpoint,
                $payload !== null ? json_encode($payload) : null,
                $severity,
            ]
        );

        // Upsert attacker profile
        $this->db->query(
            'INSERT INTO attacker_profile
             (site_id, session_key, ip_address, user_agent, browser, os, total_attempts, max_severity)
             VALUES (?, ?, ?, ?, ?, ?, 1, ?)
             ON DUPLICATE KEY UPDATE
                last_seen       = CURRENT_TIMESTAMP,
                total_attempts  = total_attempts + 1,
                max_severity    = GREATEST(max_severity, VALUES(max_severity))',
            [
                $siteId,
                $sessionKey,
                $client['ip'],
                $client['user_agent'],
                $client['browser'],
                $client['os'],
                $severity,
            ]
        );

        // Update site's last_report_at
        $this->db->query(
            'UPDATE sites SET last_report_at = CURRENT_TIMESTAMP WHERE id = ?',
            [$siteId]
        );

        $profile = $this->db->fetchOne(
            'SELECT is_banned FROM attacker_profile WHERE site_id = ? AND session_key = ?',
            [$siteId, $sessionKey]
        );

        return [
            'severity'    => $severity,
            'is_banned'   => (bool) ($profile['is_banned'] ?? false),
            'session_key' => $sessionKey,
            'client'      => $client,
        ];
    }

    /**
     * Permanently bans a session on a specific site.
     */
    public function ban(int $siteId, string $sessionKey, string $reason): void
    {
        $this->db->query(
            'UPDATE attacker_profile
             SET is_banned = 1, banned_at = CURRENT_TIMESTAMP, ban_reason = ?
             WHERE site_id = ? AND session_key = ?',
            [$reason, $siteId, $sessionKey]
        );
    }

    /**
     * Checks whether a session is currently banned on a site.
     */
    public function isBanned(int $siteId, string $sessionKey): bool
    {
        $row = $this->db->fetchOne(
            'SELECT is_banned FROM attacker_profile WHERE site_id = ? AND session_key = ?',
            [$siteId, $sessionKey]
        );
        return (bool) ($row['is_banned'] ?? false);
    }
}
