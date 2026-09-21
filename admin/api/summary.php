<?php
/**
 * admin/api/summary.php
 * Returns aggregate stats across all sites + 7-day trend + origins.
 * GET /aegis/admin/api/summary.php
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';
require_once dirname(__DIR__, 2) . '/classes/GeoLookup.php';

use Aegis\Config\Database;
use Aegis\Classes\GeoLookup;

header('Content-Type: application/json');

// --- Basic admin auth: replace with your real SIMAP session check ---
session_start();
if (empty($_SESSION['aegis_admin'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$db  = Database::getInstance();
$geo = new GeoLookup();

$totals = $db->fetchOne(
    'SELECT COUNT(*) AS total_events,
            SUM(CASE WHEN entered_username IS NOT NULL
                      OR entered_password IS NOT NULL THEN 1 ELSE 0 END) AS credentials_captured
     FROM aegis_attack_log'
) ?? ['total_events' => 0, 'credentials_captured' => 0];

$siteCount = (int) $db->fetchScalar('SELECT COUNT(*) FROM aegis_sites');

$threats = $db->fetchOne(
    'SELECT SUM(CASE WHEN is_banned = 0 THEN 1 ELSE 0 END) AS active_threats,
            SUM(CASE WHEN is_banned = 1 THEN 1 ELSE 0 END) AS banned_count
     FROM aegis_attacker_profile'
) ?? ['active_threats' => 0, 'banned_count' => 0];

$byDay = $db->fetchAll(
    'SELECT DATE(created_at) AS day, COUNT(*) AS count
     FROM aegis_attack_log
     WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
     GROUP BY DATE(created_at)
     ORDER BY day ASC'
);

$topIps = $db->fetchAll(
    'SELECT ip_address, COUNT(*) AS count
     FROM aegis_attack_log
     GROUP BY ip_address
     ORDER BY count DESC
     LIMIT 5'
);

$origins = [];
foreach ($topIps as $row) {
    $geoData  = $geo->lookup($row['ip_address']);
    $origins[] = [
        'ip'      => $row['ip_address'],
        'count'   => (int) $row['count'],
        'country' => $geoData['country'] ?? 'Unknown',
        'city'    => $geoData['city']    ?? null,
    ];
}

echo json_encode([
    'total_events'          => (int) $totals['total_events'],
    'credentials_captured'  => (int) $totals['credentials_captured'],
    'sites_count'           => $siteCount,
    'active_threats'        => (int) ($threats['active_threats'] ?? 0),
    'banned_count'          => (int) ($threats['banned_count']   ?? 0),
    'by_day'                => $byDay,
    'origins'               => $origins,
]);
