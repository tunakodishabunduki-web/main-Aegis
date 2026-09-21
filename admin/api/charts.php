<?php
/**
 * admin/api/charts.php
 * GET /aegis/admin/api/charts.php?site_id=1  — per-site chart data
 * GET /aegis/admin/api/charts.php             — cross-site overview
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';

use Aegis\Config\Database;

header('Content-Type: application/json');
session_start();
if (empty($_SESSION['aegis_admin'])) { http_response_code(401); echo json_encode(['error'=>'Unauthorized']); exit; }

$db     = Database::getInstance();
$siteId = isset($_GET['site_id']) ? (int) $_GET['site_id'] : null;

$whereClause = $siteId ? 'WHERE site_id = ?' : '';
$params      = $siteId ? [$siteId] : [];

$byDay = $db->fetchAll(
    "SELECT DATE(created_at) AS day, COUNT(*) AS count
     FROM aegis_attack_log
     {$whereClause}" . ($siteId ? ' AND ' : 'WHERE ') .
    "created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
     GROUP BY DATE(created_at)
     ORDER BY day ASC",
    $params
);

$byType = $db->fetchAll(
    "SELECT attack_type, COUNT(*) AS count
     FROM aegis_attack_log
     {$whereClause}
     GROUP BY attack_type
     ORDER BY count DESC",
    $params
);

$severityBuckets = $db->fetchOne(
    "SELECT
         SUM(CASE WHEN severity_score >= 80 THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN severity_score >= 50 AND severity_score < 80 THEN 1 ELSE 0 END) AS high,
         SUM(CASE WHEN severity_score >= 25 AND severity_score < 50 THEN 1 ELSE 0 END) AS moderate,
         SUM(CASE WHEN severity_score < 25  THEN 1 ELSE 0 END) AS low
     FROM aegis_attack_log
     {$whereClause}",
    $params
) ?? ['critical' => 0, 'high' => 0, 'moderate' => 0, 'low' => 0];

echo json_encode([
    'by_day'           => $byDay,
    'by_type'          => $byType,
    'severity_buckets' => $severityBuckets,
]);
