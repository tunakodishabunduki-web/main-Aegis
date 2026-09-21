<?php
/**
 * admin/api/ingest.php
 * Receives POST events from RemoteReporter.php on remote sites.
 * This is the central collection endpoint for API-based integration.
 *
 * POST /aegis/admin/api/ingest.php
 * Headers: X-Honeypot-Key: hp_...
 * Body: JSON event (see RemoteReporter::report())
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';
require_once dirname(__DIR__, 2) . '/classes/AttackTracker.php';
require_once dirname(__DIR__, 2) . '/classes/AlertNotifier.php';
require_once dirname(__DIR__, 2) . '/classes/SiteManager.php';

use Aegis\Config\Database;
use Aegis\Classes\{AttackTracker, AlertNotifier, SiteManager};

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Resolve site from install key
$installKey = $_SERVER['HTTP_X_HONEYPOT_KEY'] ?? '';
if (empty($installKey)) {
    http_response_code(401);
    echo json_encode(['error' => 'Missing X-Honeypot-Key']);
    exit;
}

$siteManager = new SiteManager();
$site        = $siteManager->resolveByKey($installKey);
if (!$site) {
    http_response_code(401);
    echo json_encode(['error' => 'Unknown install key']);
    exit;
}

$body = json_decode(file_get_contents('php://input') ?: '{}', true);
if (!$body || empty($body['attack_type'])) {
    http_response_code(400);
    echo json_encode(['error' => 'attack_type is required']);
    exit;
}

// Spoof $_SERVER so AttackTracker can read client IP + UA from the event data
// (the real IP/UA came from the remote site, not from this HTTP request)
$_SERVER['REMOTE_ADDR']      = $body['ip_address']  ?? $_SERVER['REMOTE_ADDR'];
$_SERVER['HTTP_USER_AGENT']  = $body['user_agent']   ?? '';

$tracker  = new AttackTracker();
$notifier = new AlertNotifier();
$siteId   = (int) $site['id'];

$result = $tracker->logEvent(
    $siteId,
    $body['attack_type'],
    $body['entered_username'] ?? null,
    $body['entered_password'] ?? null,
    $body['endpoint']         ?? null,
    $body['payload']          ?? null
);

$notifier->maybeAlert(
    $result['severity'],
    $result['session_key'],
    $result['client'],
    $body['attack_type'],
    $result['is_banned'],
    $body['entered_username'] ?? null,
    $body['entered_password'] ?? null,
    $body['endpoint']         ?? null
);

// Tell the remote site whether this is a decoy user ID (for the delete trap)
$db      = Database::getInstance();
$isDecoy = false;
if (!empty($body['target_user_id'])) {
    $decoy   = $db->fetchOne(
        'SELECT id FROM aegis_decoy_users WHERE site_id = ? AND id = ?',
        [$siteId, (int) $body['target_user_id']]
    );
    $isDecoy = (bool) $decoy;
    if ($isDecoy) {
        $tracker->ban($siteId, $result['session_key'], 'Attempted to delete a decoy user');
    }
}

echo json_encode([
    'received'   => true,
    'severity'   => $result['severity'],
    'is_banned'  => $result['is_banned'],
    'is_decoy'   => $isDecoy,
]);
