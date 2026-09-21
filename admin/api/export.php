<?php
/**
 * admin/api/export.php
 * GET /aegis/admin/api/export.php             — all sites, full attack log as CSV
 * GET /aegis/admin/api/export.php?site_id=1   — filter to one site
 */

declare(strict_types=1);
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

$where  = $siteId ? 'WHERE al.site_id = ?' : '';
$params = $siteId ? [$siteId] : [];

$rows = $db->fetchAll(
    "SELECT al.id, s.site_name, s.site_url,
            al.session_key, al.ip_address, al.browser, al.os,
            al.attack_type, al.entered_username, al.entered_password,
            al.endpoint, al.severity_score, al.source, al.created_at
     FROM aegis_attack_log al
     JOIN aegis_sites s ON s.id = al.site_id
     {$where}
     ORDER BY al.created_at DESC",
    $params
);

$suffix   = $siteId ? "-site-{$siteId}" : '-all-sites';
$filename = 'aegis-attack-log' . $suffix . '-' . date('Y-m-d') . '.csv';

header('Content-Type: text/csv; charset=UTF-8');
header("Content-Disposition: attachment; filename=\"{$filename}\"");
// BOM for Excel compatibility
echo "\xEF\xBB\xBF";

$out = fopen('php://output', 'w');
fputcsv($out, [
    'id', 'site_name', 'site_url', 'session_key', 'ip_address',
    'browser', 'os', 'attack_type', 'entered_username', 'entered_password',
    'endpoint', 'severity_score', 'source', 'created_at'
]);

foreach ($rows as $row) {
    fputcsv($out, array_values($row));
}

fclose($out);
