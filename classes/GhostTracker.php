<?php
/**
 * GhostTracker.php
 * ============================================================
 * Plants forensic breadcrumb IDs in all decoy/fake responses.
 * If the attacker later uses any of these Ghost IDs in a real
 * GET request, Aegis knows their stolen data is in active use —
 * even from a completely different IP.
 *
 * Ghost ID format:  ghost_{timestamp}_{ip_hash}_{system_code}
 * Example:          ghost_1735123456_a3f8b2c1_EDU
 *
 * When a Ghost ID is detected in any incoming request:
 *   1. Severity escalated to maximum (99)
 *   2. Session immediately banned
 *   3. Real-time alert fires (WhatsApp + physical tracker)
 *   4. Ghost ID recorded as "confirmed in-use" in the DB
 *   5. All related sessions across ALL sites searched
 *      (same IP hash = same attacker infrastructure)
 * ============================================================
 */

namespace Aegis\Classes;

use Aegis\Config\Database;

class GhostTracker
{
    public const GHOST_PREFIX   = 'ghost_';
    public const GHOST_PATTERN  = '/^ghost_\d+_[a-f0-9]+_[A-Z]+$/';

    // System type → 3-letter code embedded in the ghost ID
    // Tells you which system's data the attacker is using
    private const SYSTEM_CODES = [
        'ECOMMERCE'        => 'ECO',
        'SAAS'             => 'SAS',
        'HEALTHCARE'       => 'HLT',
        'EDUCATION'        => 'EDU',
        'WIFI_MANAGEMENT'  => 'WFI',
        'AGENCY'           => 'AGY',
        'PROPERTY'         => 'PRP',
        'RESTAURANT'       => 'RST',
        'GENERIC_BUSINESS' => 'GEN',
    ];

    private Database      $db;
    private AttackTracker $tracker;
    private AlertNotifier $notifier;

    public function __construct()
    {
        $this->db      = Database::getInstance();
        $this->tracker = new AttackTracker();
        $this->notifier= new AlertNotifier();
    }

    // ================================================================
    //  GENERATION  —  called when building fake/decoy responses
    // ================================================================

    /**
     * Generates a ghost ID and stores it in the DB for later detection.
     * Embed this in fake transaction IDs, fake user IDs, fake invoice
     * numbers — anywhere the attacker might re-use the data.
     *
     * @param int    $siteId
     * @param string $sessionKey  The attacker's current session
     * @param string $systemType
     * @param string $context     What field this is being embedded in
     * @return string             The ghost ID to embed in the response
     */
    public function generate(int $siteId, string $sessionKey,
                             string $systemType, string $context = 'id'): string
    {
        $timestamp  = time();
        $ipHash     = substr(md5($this->getClientIp()), 0, 8);
        $sysCode    = self::SYSTEM_CODES[$systemType] ?? 'GEN';
        $ghostId    = self::GHOST_PREFIX . $timestamp . '_' . $ipHash . '_' . $sysCode;

        // Store it so we can recognise it when they come back
        $this->store($ghostId, $siteId, $sessionKey, $systemType, $context);

        return $ghostId;
    }

    /**
     * Generates multiple ghost IDs for a response that has many IDs.
     * Returns an array of ghost IDs.
     */
    public function generateBatch(int $siteId, string $sessionKey,
                                  string $systemType, int $count = 5): array
    {
        $ids = [];
        for ($i = 0; $i < $count; $i++) {
            usleep(1000); // 1ms gap so timestamps differ
            $ids[] = $this->generate($siteId, $sessionKey, $systemType, "batch_{$i}");
        }
        return $ids;
    }

    /**
     * Injects ghost IDs into a fake response array.
     * Replaces numeric/string IDs in the response with ghost IDs.
     * Works recursively on nested arrays.
     */
    public function injectIntoResponse(
        array  $response,
        int    $siteId,
        string $sessionKey,
        string $systemType
    ): array {
        return $this->injectRecursive($response, $siteId, $sessionKey, $systemType, 0);
    }

    private function injectRecursive(
        array $data, int $siteId, string $sessionKey,
        string $systemType, int $depth
    ): array {
        if ($depth > 3) return $data; // don't go too deep

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->injectRecursive(
                    $value, $siteId, $sessionKey, $systemType, $depth + 1
                );
            } elseif ($key === 'id' || $key === 'transaction_id' ||
                      $key === 'invoice_id' || $key === 'order_id' ||
                      $key === 'session_key' || $key === 'token') {
                // Replace real-looking IDs with ghost IDs
                $data[$key] = $this->generate($siteId, $sessionKey, $systemType, $key);
            }
        }
        return $data;
    }

    // ================================================================
    //  DETECTION  —  called on every incoming request
    // ================================================================

    /**
     * Scans all request parameters for any ghost ID.
     * Call this from Middleware before routing.
     *
     * @return bool  true if a ghost ID was found (triggers escalation)
     */
    public function checkRequest(
        array  $params,
        int    $siteId,
        string $sessionKey,
        string $systemType
    ): bool {
        $allValues = $this->flattenValues($params);

        foreach ($allValues as $value) {
            if (is_string($value) && $this->isGhostId($value)) {
                $this->triggerGhostDetected($value, $siteId, $sessionKey, $systemType);
                return true;
            }
        }
        return false;
    }

    /**
     * Checks a single value (e.g. route segment /payments/ghost_xxx).
     */
    public function checkValue(string $value, int $siteId,
                               string $sessionKey, string $systemType): bool
    {
        if (!$this->isGhostId($value)) return false;
        $this->triggerGhostDetected($value, $siteId, $sessionKey, $systemType);
        return true;
    }

    /**
     * Returns true if the string matches the ghost ID pattern.
     */
    public function isGhostId(string $value): bool
    {
        return str_starts_with($value, self::GHOST_PREFIX) &&
               preg_match(self::GHOST_PATTERN, $value);
    }

    // ================================================================
    //  DASHBOARD QUERY  —  list all active ghost IDs
    // ================================================================

    public function listActive(int $siteId): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM aegis_ghost_ids
             WHERE site_id = ? ORDER BY created_at DESC LIMIT 50',
            [$siteId]
        );
    }

    public function listTriggered(int $siteId): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM aegis_ghost_ids
             WHERE site_id = ? AND triggered = 1
             ORDER BY triggered_at DESC LIMIT 50',
            [$siteId]
        );
    }

    // ================================================================
    //  PRIVATE
    // ================================================================

    private function store(string $ghostId, int $siteId, string $sessionKey,
                           string $systemType, string $context): void
    {
        $this->db->query(
            'INSERT IGNORE INTO aegis_ghost_ids
             (ghost_id, site_id, session_key, system_type, context, created_at)
             VALUES (?, ?, ?, ?, ?, NOW())',
            [$ghostId, $siteId, $sessionKey, $systemType, $context]
        );
    }

    private function triggerGhostDetected(string $ghostId, int $siteId,
                                          string $sessionKey, string $systemType): void
    {
        // 1. Mark ghost ID as triggered in DB
        $this->db->query(
            'UPDATE aegis_ghost_ids SET triggered = 1, triggered_at = NOW(),
             triggered_by_session = ?, triggered_by_ip = ?
             WHERE ghost_id = ?',
            [$sessionKey, $this->getClientIp(), $ghostId]
        );

        // 2. Try to find the ORIGINAL session that received this ghost ID
        $original = $this->db->fetchOne(
            'SELECT session_key, site_id FROM aegis_ghost_ids WHERE ghost_id = ?',
            [$ghostId]
        );

        // 3. Log at maximum severity
        $client = $this->tracker->getClientDetails();
        $this->tracker->logEvent(
            $siteId,
            'GHOST_ID_TRIGGERED',
            null, null,
            $_SERVER['REQUEST_URI'] ?? '/',
            [
                'ghost_id'         => $ghostId,
                'original_session' => $original['session_key'] ?? 'unknown',
                'confirms'         => 'Attacker is actively using stolen decoy data',
            ]
        );

        // 4. Immediately ban this session
        $this->tracker->ban($siteId, $sessionKey,
            "Ghost ID confirmed in use: {$ghostId}");

        // 5. Also ban the original session if still active
        if ($original && $original['session_key'] !== $sessionKey) {
            $this->tracker->ban(
                (int) $original['site_id'],
                $original['session_key'],
                "Related session: Ghost ID used by another IP"
            );
        }

        // 6. Fire maximum-severity alert
        $this->notifier->maybeAlert(
            99,
            $sessionKey,
            $client,
            'GHOST_ID_TRIGGERED',
            true
        );
    }

    private function isGhostIdReal(string $ghostId): bool
    {
        $row = $this->db->fetchOne(
            'SELECT id FROM aegis_ghost_ids WHERE ghost_id = ? AND triggered = 0',
            [$ghostId]
        );
        return (bool) $row;
    }

    private function getClientIp(): string
    {
        return trim(explode(',',
            $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
        )[0]);
    }

    private function flattenValues(array $arr, int $depth = 0): array
    {
        if ($depth > 4) return [];
        $out = [];
        foreach ($arr as $v) {
            if (is_array($v)) {
                $out = array_merge($out, $this->flattenValues($v, $depth + 1));
            } else {
                $out[] = $v;
            }
        }
        return $out;
    }
}
