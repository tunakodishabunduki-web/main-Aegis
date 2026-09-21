<?php
/**
 * admin/api/sites.php
 * GET  /aegis/admin/api/sites.php           — list all sites
 * POST /aegis/admin/api/sites.php           — register new site
 * GET  /aegis/admin/api/sites.php?health=1  — live health of all sites
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';
require_once dirname(__DIR__, 2) . '/classes/SiteManager.php';
require_once dirname(__DIR__, 2) . '/classes/HelperClasses.php';

use Aegis\Config\Database;
use Aegis\Classes\{SiteManager, SiteHealth};

header('Content-Type: application/json');
session_start();
if (empty($_SESSION['aegis_admin'])) { http_response_code(401); echo json_encode(['error'=>'Unauthorized']); exit; }

$manager = new SiteManager();
$method  = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST') {
    $body     = json_decode(file_get_contents('php://input') ?: '{}', true) ?? [];
    $siteUrl  = trim($body['site_url']  ?? '');
    $siteName = trim($body['site_name'] ?? '');

    if (empty($siteUrl) || filter_var($siteUrl, FILTER_VALIDATE_URL) === false) {
        http_response_code(400);
        echo json_encode(['error' => 'Valid site_url is required']);
        exit;
    }

    echo json_encode($manager->registerSite($siteUrl, $siteName));
    exit;
}

// GET
if (isset($_GET['health'])) {
    $db    = Database::getInstance();
    $sites = $db->fetchAll('SELECT id, site_url FROM aegis_sites');
    $check = new SiteHealth();
    echo json_encode(['results' => $check->checkAll($sites)]);
    exit;
}

echo json_encode(['sites' => $manager->listSites()]);
