<?php
/**
 * admin/api/lessons.php
 * GET /aegis/admin/api/lessons.php?site_id=1  — ranked lessons for one site
 * GET /aegis/admin/api/lessons.php             — cross-site aggregate lessons
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';
require_once dirname(__DIR__, 2) . '/classes/AttackEducation.php';

use Aegis\Config\Database;
use Aegis\Classes\AttackEducation;

header('Content-Type: application/json');
session_start();
if (empty($_SESSION['aegis_admin'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$db     = Database::getInstance();
$siteId = isset($_GET['site_id']) ? (int) $_GET['site_id'] : null;

$where  = $siteId ? 'WHERE site_id = ?' : '';
$params = $siteId ? [$siteId] : [];

$events = $db->fetchAll(
    "SELECT attack_type FROM aegis_attack_log {$where}",
    $params
);

echo json_encode(['lessons' => AttackEducation::summarizeLessons($events)]);
