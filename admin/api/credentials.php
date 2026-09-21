<?php
/**
 * admin/api/credentials.php
 * GET /aegis/admin/api/credentials.php?site_id=1  — captured login credentials
 *
 * admin/api/export.php
 * GET /aegis/admin/api/export.php?site_id=1  — download CSV of all attack events
 */

declare(strict_types=1);

// Detect which endpoint was requested by URL
$script = basename(__FILE__);

require_once dirname(__DIR__, 2) . '/config/Database.php';

use Aegis\Config\Database;

session_start();
if (empty($_SESSION['aegis_admin'])) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$db     = Database::getInstance();
$siteId = isset($_GET['site_id']) ? (int) $_GET['site_id'] : null;

if ($script === 'credentials.php') {
    header('Content-Type: application/json');

    $where  = $siteId ? 'AND site_id = ?' : '';
    $params = $siteId ? [$siteId] : [];

    $rows = $db->fetchAll(
        "SELECT entered_username, entered_password, ip_address,
                attack_type, severity_score, site_id, created_at
         FROM aegis_attack_log
         WHERE (entered_username IS NOT NULL OR entered_password IS NOT NULL)
         {$where}
         ORDER BY created_at DESC
         LIMIT 200",
        $params
    );

    echo json_encode(['credentials' => $rows]);
    exit;
}

// export.php — CSV download
$where  = $siteId ? 'WHERE site_id = ?' : '';
$params = $siteId ? [$siteId] : [];

$rows = $db->fetchAll(
    "SELECT site_id, session_key, ip_address, browser, os, attack_type,
            entered_username, entered_password, endpoint, severity_score, created_at
     FROM aegis_attack_log
     {$where}
     ORDER BY created_at DESC",
    $params
);

$filename = 'aegis-attack-log' . ($siteId ? "-site-{$siteId}" : '') . '.csv';
header('Content-Type: text/csv');
header("Content-Disposition: attachment; filename=\"{$filename}\"");

$out = fopen('php://output', 'w');
fputcsv($out, ['site_id','session_key','ip_address','browser','os',
               'attack_type','entered_username','entered_password',
               'endpoint','severity_score','created_at']);

foreach ($rows as $row) {
    fputcsv($out, array_values($row));
}
fclose($out);
