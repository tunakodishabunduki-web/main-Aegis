<?php
/**
 * USAGE EXAMPLES
 * ============================================================
 * Shows how Authorization.php and the updated AdvancedDetection.php
 * work together in real endpoint files.
 *
 * These are EXAMPLE files — copy the pattern into your own endpoints.
 * ============================================================
 */

// ============================================================
// EXAMPLE 1: Invoices endpoint — role + ownership (anti-IDOR)
// File: api/invoices.php
// ============================================================

require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../classes/Authorization.php';
require_once __DIR__ . '/../classes/AdvancedDetection.php';
require_once __DIR__ . '/../classes/AttackTracker.php';

use Aegis\Classes\{Authorization, AdvancedDetection, AttackTracker};
use Aegis\Config\Database;

session_start();

// Build the authorizer from the current session (SIMAP-style)
$auth = Authorization::fromSession();

$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';

// ── GET /api/invoices/{id} ──────────────────────────────────
if ($method === 'GET' && preg_match('#^/api/invoices/(\d+)$#', $path, $m)) {
    $invoiceId = (int) $m[1];

    // One line: checks role AND that this user owns invoice #{$invoiceId}
    // CLIENT can only read their own. MANAGER+ can read any.
    $auth->guard('GET', $path, 'invoices', $invoiceId);

    $db      = Database::getInstance();
    // Parameterised query — the ACTUAL defence against SQLi
    $invoice = $db->fetchOne(
        'SELECT * FROM invoices WHERE id = ? AND user_id = ?',
        [$invoiceId, $_SESSION['user_id']]
        // ↑ Double-lock: Authorization already checked ownership,
        //   but the query also enforces it at DB level.
        //   Even if Authorization.php has a bug, the query saves you.
    );

    header('Content-Type: application/json');
    echo json_encode($invoice ?? ['error' => 'Not found']);
    exit;
}

// ── DELETE /api/invoices/{id} ───────────────────────────────
if ($method === 'DELETE' && preg_match('#^/api/invoices/(\d+)$#', $path, $m)) {
    $invoiceId = (int) $m[1];

    // Only MANAGER and above can delete any invoice
    $auth->requireRole('MANAGER');

    $db = Database::getInstance();
    $db->query('DELETE FROM invoices WHERE id = ?', [$invoiceId]);

    header('Content-Type: application/json');
    echo json_encode(['deleted' => true]);
    exit;
}


// ============================================================
// EXAMPLE 2: Search endpoint — detect encoded payloads
// File: api/search.php
// ============================================================

$auth->requireRole('CLIENT'); // must be logged in at minimum

$query = $_GET['q'] ?? '';

// classify() now decodes: URL, HTML entities, hex, base64,
// full-width unicode, SQL comment stripping — before regex
$attackType = AdvancedDetection::classify($query);

if ($attackType) {
    // Log the decoded-and-detected attack
    $tracker = new AttackTracker();
    $siteId  = (int) ($_SESSION['site_id'] ?? 1);
    $tracker->logEvent(
        $siteId,
        $attackType,
        $_SESSION['user_id'] ?? null,
        null,
        $path,
        ['raw' => $query, 'normalised' => AdvancedDetection::normalise($query)]
        // ↑ Store both raw and normalised payload in the dashboard
        //   so you can see exactly what encoding was stripped
    );

    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

// Clean input — parameterised query does the actual safety work
$db      = Database::getInstance();
$results = $db->fetchAll(
    'SELECT id, title, summary FROM posts WHERE title LIKE ?',
    ['%' . $query . '%']
    // ↑ NEVER: "WHERE title LIKE '%" . $query . "%'"
    //   Even though AdvancedDetection caught the payload,
    //   the parameterised query is your real protection.
    //   Both layers working together is defence-in-depth.
);

header('Content-Type: application/json');
echo json_encode(['results' => $results]);
exit;


// ============================================================
// EXAMPLE 3: Admin users endpoint — role gate only
// File: admin/api/users.php
// ============================================================

// Only ADMIN can list all users — no ownership check needed
// because admins see everything
$auth->requireRole('ADMIN');

// Scan ALL query parameters, not just one field
$allInput = implode(' ', array_merge(
    array_values($_GET),
    array_values($_POST)
));

$attackType = AdvancedDetection::classify($allInput);
if ($attackType) {
    $tracker = new AttackTracker();
    $tracker->logEvent(1, $attackType, null, null, $path, $_REQUEST);
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

$db    = Database::getInstance();
$users = $db->fetchAll('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC');
echo json_encode(['users' => $users]);
exit;


// ============================================================
// EXAMPLE 4: Profile update — own account only
// File: api/profile.php
// ============================================================

if ($method === 'PUT') {
    // Anyone CLIENT+ can update — but ONLY their own profile
    $auth->requireRole('CLIENT');

    $targetUserId = (int) ($_GET['id'] ?? $_SESSION['user_id']);

    // IDOR prevention: are you updating YOUR profile or someone else's?
    if (!$auth->hasRole('ADMIN') && $targetUserId !== (int) $_SESSION['user_id']) {
        http_response_code(403);
        echo json_encode(['error' => 'You can only update your own profile']);
        exit;
    }

    $body  = json_decode(file_get_contents('php://input') ?: '{}', true) ?? [];
    $email = $body['email'] ?? '';
    $name  = $body['name']  ?? '';

    // Scan the incoming JSON body for attack payloads
    $combined   = $email . ' ' . $name;
    $attackType = AdvancedDetection::classify($combined);

    if ($attackType) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid input']);
        exit;
    }

    // Parameterised update — safe from SQLi regardless of detection
    $db = Database::getInstance();
    $db->query(
        'UPDATE users SET email = ?, name = ? WHERE id = ?',
        [
            filter_var($email, FILTER_SANITIZE_EMAIL),
            htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
            $targetUserId
        ]
    );

    echo json_encode(['updated' => true]);
    exit;
}


// ============================================================
// EXAMPLE 5: Finance report — role OR ownership
// File: api/reports/{id}.php
// ============================================================

if ($method === 'GET' && preg_match('#^/api/reports/(\d+)$#', $path, $m)) {
    $reportId = (int) $m[1];

    // MANAGER+ can read any report.
    // FINANCE can only read reports they created themselves.
    $auth->requireRoleOrOwnership('MANAGER', 'reports', $reportId);

    $db     = Database::getInstance();
    $report = $db->fetchOne(
        // Still scope to owner in the query — double-lock
        $auth->hasRole('MANAGER')
            ? 'SELECT * FROM reports WHERE id = ?'
            : 'SELECT * FROM reports WHERE id = ? AND created_by = ?',
        $auth->hasRole('MANAGER')
            ? [$reportId]
            : [$reportId, $_SESSION['user_id']]
    );

    echo json_encode($report ?? ['error' => 'Not found']);
    exit;
}
