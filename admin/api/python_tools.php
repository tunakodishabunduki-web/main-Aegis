<?php
/**
 * admin/api/python_tools.php
 * GET /aegis/admin/api/python_tools.php?action=status
 * GET /aegis/admin/api/python_tools.php?action=threat_summary
 * GET /aegis/admin/api/python_tools.php?action=deception_status
 * GET /aegis/admin/api/python_tools.php?action=network_summary
 * POST /aegis/admin/api/python_tools.php   body: {"action":"check_ioc","indicator":"..."}
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/config/Database.php';
require_once dirname(__DIR__, 2) . '/bridge/PythonBridge.php';
require_once dirname(__DIR__, 2) . '/classes/AttackEducation.php';

use Aegis\Config\Database;
use Aegis\Bridge\PythonBridge;
use Aegis\Classes\AttackEducation;

header('Content-Type: application/json');
session_start();
if (empty($_SESSION['aegis_admin'])) { http_response_code(401); echo json_encode(['error'=>'Unauthorized']); exit; }

$bridge = new PythonBridge();
$method = $_SERVER['REQUEST_METHOD'];
$action = '';

if ($method === 'POST') {
    $body   = json_decode(file_get_contents('php://input') ?: '{}', true) ?? [];
    $action = $body['action'] ?? '';
} else {
    $action = $_GET['action'] ?? 'status';
}

switch ($action) {
    case 'status':
        echo json_encode(['modules' => $bridge->moduleStatus()]);
        break;

    case 'threat_summary':
        echo json_encode($bridge->threatIntelSummary());
        break;

    case 'threat_collect':
        echo json_encode($bridge->threatIntelCollect());
        break;

    case 'check_ioc':
        $indicator = $body['indicator'] ?? $_GET['indicator'] ?? '';
        if (empty($indicator)) {
            http_response_code(400);
            echo json_encode(['error' => 'indicator is required']);
        } else {
            echo json_encode($bridge->checkIoc($indicator));
        }
        break;

    case 'deception_status':
        echo json_encode($bridge->deceptionStatus());
        break;

    case 'network_summary':
        echo json_encode($bridge->networkSummary());
        break;

    case 'tracker_status':
        echo json_encode($bridge->trackerStatus());
        break;

    case 'network_alerts':
        echo json_encode($bridge->networkAlerts());
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => "Unknown action: {$action}"]);
}
