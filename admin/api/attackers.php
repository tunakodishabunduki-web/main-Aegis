<?php
/**
 * admin/api/attackers.php
 * GET /aegis/admin/api/attackers.php?site_id=1
 * GET /aegis/admin/api/attackers.php?site_id=1&session_key=abc123
 * GET /aegis/admin/api/attackers.php?site_id=1&session_key=abc123&report=pdf
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';
require_once dirname(__DIR__, 2) . '/classes/AttackEducation.php';
require_once dirname(__DIR__, 2) . '/classes/HelperClasses.php';

use Aegis\Config\Database;
use Aegis\Classes\{AttackEducation, ReportGenerator};

header('Content-Type: application/json');
session_start();
if (empty($_SESSION['aegis_admin'])) { http_response_code(401); echo json_encode(['error'=>'Unauthorized']); exit; }

$db      = Database::getInstance();
$siteId  = isset($_GET['site_id']) ? (int) $_GET['site_id'] : null;
$sessKey = $_GET['session_key'] ?? null;

if ($siteId && $sessKey) {
    // Single attacker detail + events
    if (isset($_GET['report']) && $_GET['report'] === 'pdf') {
        $gen = new ReportGenerator();
        $gen->streamReport($siteId, $sessKey);
        exit;
    }

    $attacker = $db->fetchOne(
        'SELECT * FROM aegis_attacker_profile WHERE site_id = ? AND session_key = ?',
        [$siteId, $sessKey]
    );

    $events = $db->fetchAll(
        'SELECT attack_type, entered_username, entered_password,
                endpoint, payload, severity_score, source, created_at
         FROM aegis_attack_log
         WHERE site_id = ? AND session_key = ?
         ORDER BY created_at ASC',
        [$siteId, $sessKey]
    );

    echo json_encode(['attacker' => $attacker, 'events' => $events]);
    exit;
}

if ($siteId) {
    // All attackers for one site
    $attackers = $db->fetchAll(
        'SELECT session_key, ip_address, browser, os,
                first_seen, last_seen, total_attempts,
                max_severity, is_banned, ban_reason
         FROM aegis_attacker_profile
         WHERE site_id = ?
         ORDER BY last_seen DESC
         LIMIT 100',
        [$siteId]
    );
    echo json_encode(['attackers' => $attackers]);
    exit;
}

// All attackers across all sites
$attackers = $db->fetchAll(
    'SELECT ap.*, s.site_name
     FROM aegis_attacker_profile ap
     JOIN aegis_sites s ON s.id = ap.site_id
     ORDER BY ap.last_seen DESC
     LIMIT 100'
);
echo json_encode(['attackers' => $attackers]);
