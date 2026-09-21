<?php
/**
 * Middleware.php
 * ============================================================
 * Drop into any PHP project. Runs ALL 8 defenses automatically,
 * prioritised based on the type of system being protected.
 *
 * Usage (in the site's index.php, BEFORE your router):
 *   define('AEGIS_INSTALL_KEY', 'hp_...');
 *   require_once __DIR__ . '/aegis/aegis-bootstrap.php';
 *
 * Defense pipeline (in order):
 *   1. LanguageDeception   — fake tech headers on EVERY request
 *   2. LatencyInjector     — adversarial delay for cloud/VPN/Tor IPs
 *   3. ScorchedEarth       — sentinel UUID tripwire check
 *   4. GhostTracker        — forensic ID detection in request params
 *   5. AdvancedDetection   — 8-layer decode + attack classification
 *   6. Diversion           — AI honeypot for confirmed attackers
 *   7. BlackholeSink       — fake 202 for POST/DELETE floods
 *   8. DossierGenerator    — forensic PDF on later requests
 *   9. LegalThreatInjector — Tanzania CCA embedded in 403s
 * ============================================================
 */

namespace Aegis\Honeypot;

use Aegis\Classes\{
    AttackTracker, AdvancedDetection, AlertNotifier, Diversion,
    SiteManager, LanguageDeception, SystemProfiler, AttackerProfiler,
    SecurityPriorityEngine, ScorchedEarth, GhostTracker,
    LegalThreatInjector, DossierGenerator, LatencyInjector,
    BlackholeSink, ToxicJson, PoisonedCache
};
use Aegis\Config\Database;

class Middleware
{
    private AttackTracker       $tracker;
    private AlertNotifier       $notifier;
    private Diversion           $diversion;
    private SiteManager         $siteManager;
    private SecurityPriorityEngine $priorityEngine;
    private ?int                $siteId = null;

    private const HONEYPOT_PATHS = [
        '/admin-legacy', '/api/v1/admin', '/wp-admin',
        '/api/config',   '/.env',         '/api/backup',
        '/phpmyadmin',   '/.git/config',  '/api/debug',
        '/server-status','/actuator',      '/console',
    ];

    public function __construct()
    {
        $this->tracker       = new AttackTracker();
        $this->notifier      = new AlertNotifier();
        $this->diversion     = new Diversion();
        $this->siteManager   = new SiteManager();
        $this->priorityEngine= new SecurityPriorityEngine();
    }

    public function handle(): void
    {
        $installKey = defined('AEGIS_INSTALL_KEY')
            ? AEGIS_INSTALL_KEY
            : ($_SERVER['HTTP_X_HONEYPOT_KEY'] ?? '');
        if (empty($installKey)) return;

        $site = $this->siteManager->resolveByKey($installKey);
        if (!$site) return;

        $this->siteId = (int) $site['id'];

        // ── STEP 1: Language deception on every request ─────────────
        // Even legitimate curl -I / WhatWeb scans see Django/Node, not PHP
        LanguageDeception::applyAll($this->siteId);

        $path    = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
        $method  = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $ua      = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $qs      = $_SERVER['QUERY_STRING'] ?? '';
        $client  = $this->tracker->getClientDetails();
        $sessKey = $client['session_key'];

        // Detect system type for priority-based defense
        $sysProfiler = new SystemProfiler();
        $systemType  = $sysProfiler->detect($this->siteId);

        // Load current attacker profile for priority engine
        $db      = Database::getInstance();
        $profile = $db->fetchOne(
            'SELECT max_severity, is_banned FROM aegis_attacker_profile
             WHERE site_id = ? AND session_key = ?',
            [$this->siteId, $sessKey]
        );
        $severity   = (int) ($profile['max_severity'] ?? 0);
        $isBanned   = (bool) ($profile['is_banned']   ?? false);

        // Get event history for profiler
        $events = $db->fetchAll(
            'SELECT attack_type, severity_score, created_at
             FROM aegis_attack_log
             WHERE site_id = ? AND session_key = ?
             ORDER BY created_at ASC LIMIT 30',
            [$this->siteId, $sessKey]
        );
        $profiler       = new AttackerProfiler();
        $attackerProfile= $profiler->summarise($events);
        $skillLevel     = $attackerProfile['skill_level'];
        $phase          = $attackerProfile['phase'];

        // Get the priority stack for this context
        $stack = $this->priorityEngine->getPriorityStack(
            $systemType, $skillLevel, $phase, $severity
        );

        // ── STEP 2: Latency injection ────────────────────────────────
        $latencyIntensity = $stack[SecurityPriorityEngine::LATENCY_INJECT]
                            ?? SecurityPriorityEngine::OFF;
        if ($latencyIntensity > SecurityPriorityEngine::OFF) {
            $injector = new LatencyInjector();
            if ($isBanned || $severity >= 60) {
                $injector->delayAttacker($severity, $systemType, $phase, $latencyIntensity);
            } else {
                $injector->maybeDelay($latencyIntensity);
            }
        }

        // ── STEP 3: Scorched Earth tripwire ─────────────────────────
        $seIntensity = $stack[SecurityPriorityEngine::SCORCHED_EARTH]
                       ?? SecurityPriorityEngine::OFF;
        if ($seIntensity > SecurityPriorityEngine::OFF) {
            $se     = new ScorchedEarth();
            $params = array_merge($_GET, $_POST,
                        json_decode(file_get_contents('php://input') ?: '{}', true) ?? []);
            if ($se->checkRequest($params, $this->siteId, $sessKey, $systemType)) {
                // Tripwire fired — session is already banned inside checkRequest
                $this->servePostTripwireResponse($this->siteId, $sessKey, $systemType);
            }
            // Also check route segments
            $routeId = basename($path);
            if ($se->checkValue($routeId, $this->siteId, $sessKey, $systemType)) {
                $this->servePostTripwireResponse($this->siteId, $sessKey, $systemType);
            }
        }

        // ── STEP 4: Ghost ID detection ───────────────────────────────
        $ghostIntensity = $stack[SecurityPriorityEngine::GHOST_TRACKER]
                          ?? SecurityPriorityEngine::OFF;
        if ($ghostIntensity > SecurityPriorityEngine::OFF) {
            $ghost  = new GhostTracker();
            $params = array_merge($_GET, $_POST,
                        json_decode(file_get_contents('php://input') ?: '{}', true) ?? []);
            if ($ghost->checkRequest($params, $this->siteId, $sessKey, $systemType)) {
                // Ghost ID confirmed in use — session banned, serve final response
                $this->serveBannedResponse($this->siteId, $sessKey, $path);
            }
            if ($ghost->checkValue(basename($path), $this->siteId, $sessKey, $systemType)) {
                $this->serveBannedResponse($this->siteId, $sessKey, $path);
            }
        }

        // ── STEP 5: Scanner UA check ─────────────────────────────────
        if (AdvancedDetection::isScanner($ua)) {
            $result = $this->tracker->logEvent(
                $this->siteId, 'SCANNER_TOOL_DETECTED',
                null, null, $path, ['ua' => $ua]
            );
            $this->maybeAlert($result, $client, 'SCANNER_TOOL_DETECTED', $systemType);
        }

        // ── STEP 6: Honeypot route detection ────────────────────────
        if (in_array($path, self::HONEYPOT_PATHS, true)) {
            $result = $this->tracker->logEvent(
                $this->siteId, 'HONEYPOT_ROUTE_HIT',
                null, null, $path, null
            );
            $this->maybeAlert($result, $client, 'HONEYPOT_ROUTE_HIT', $systemType);
            $this->diversion->serveDecoy($this->siteId, $sessKey, $method, $path);
        }

        // ── STEP 7: Parameter pollution check ───────────────────────
        if (AdvancedDetection::hasParameterPollution($qs)) {
            $result = $this->tracker->logEvent(
                $this->siteId, 'PARAMETER_POLLUTION_ATTEMPT',
                null, null, $path, ['qs' => $qs]
            );
            $this->maybeAlert($result, $client, 'PARAMETER_POLLUTION_ATTEMPT', $systemType);
        }

        // ── STEP 8: Divert confirmed attackers ───────────────────────
        if ($this->diversion->shouldDivert($this->siteId, $sessKey)) {

            // Blackhole POST/DELETE floods before full diversion
            $bhIntensity = $stack[SecurityPriorityEngine::BLACKHOLE_SINK]
                           ?? SecurityPriorityEngine::OFF;
            $bh = new BlackholeSink();
            if ($bh->shouldBlackhole($method, $severity, $bhIntensity)) {
                $bh->serve($method, $path);
            }

            // Serve dossier PDF on later requests (not the first one)
            $dossierIntensity = $stack[SecurityPriorityEngine::DOSSIER_PDF]
                                ?? SecurityPriorityEngine::OFF;
            if ($method === 'GET' && $dossierIntensity >= SecurityPriorityEngine::MEDIUM) {
                $dossier = new DossierGenerator();
                if ($dossier->shouldServeDossier($sessKey, $dossierIntensity)) {
                    $dossier->serveDossier(
                        $this->siteId, $sessKey, $systemType, $dossierIntensity
                    );
                }
            }

            // Full AI honeypot diversion
            $this->diversion->serveDecoy($this->siteId, $sessKey, $method, $path);
        }

        // ── STEP 9: Login inspection ─────────────────────────────────
        if (in_array($path, ['/api/login','/login','/api/auth','/admin/login'], true)) {
            $body     = json_decode(file_get_contents('php://input') ?: '{}', true) ?? [];
            $username = $body['username'] ?? $_POST['username'] ?? null;
            $password = $body['password'] ?? $_POST['password'] ?? null;

            if ($username || $password) {
                $combined   = ($username ?? '') . ' ' . ($password ?? '');
                $attackType = AdvancedDetection::classify($combined);

                if ($attackType) {
                    $result = $this->tracker->logEvent(
                        $this->siteId, $attackType,
                        $username, $password, $path, null
                    );
                    $this->maybeAlert($result, $client, $attackType, $systemType);

                    // Inject legal threat into response if appropriate
                    $ltIntensity = $stack[SecurityPriorityEngine::LEGAL_THREAT]
                                   ?? SecurityPriorityEngine::OFF;
                    if ($ltIntensity >= SecurityPriorityEngine::MEDIUM &&
                        $result['severity'] >= 50) {
                        $injector = new LegalThreatInjector();
                        http_response_code(403);
                        header('Content-Type: application/json');
                        echo json_encode(
                            $injector->buildLegalResponse(
                                $sessKey, $attackType,
                                $result['severity'], $ltIntensity
                            )
                        );
                        exit;
                    }
                } else {
                    // Normal failed login
                    $result = $this->tracker->logEvent(
                        $this->siteId, 'FAILED_LOGIN',
                        $username, $password, $path, null
                    );
                    $this->maybeAlert($result, $client, 'FAILED_LOGIN', $systemType);
                }
            }
        }

        // ── STEP 10: General payload scan (all other requests) ───────
        $allInput = $this->collectInput();
        if (!empty($allInput)) {
            $attackType = AdvancedDetection::classify($allInput);
            if ($attackType) {
                $result = $this->tracker->logEvent(
                    $this->siteId, $attackType,
                    null, null, $path,
                    ['raw' => substr($allInput, 0, 300),
                     'normalised' => AdvancedDetection::normalise($allInput)]
                );
                $this->maybeAlert($result, $client, $attackType, $systemType);

                // Log fired defenses for audit
                $this->logDefenses($stack, $systemType, $skillLevel, $phase, $severity);
            }
        }

        // Real app continues from here — Aegis is done with this request
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private function maybeAlert(array $result, array $client,
                                string $attackType, string $systemType): void
    {
        $this->notifier->maybeAlert(
            $result['severity'], $result['session_key'], $client,
            $attackType, $result['is_banned']
        );
    }

    private function collectInput(): string
    {
        $parts = [
            http_build_query($_GET),
            http_build_query($_POST),
            file_get_contents('php://input') ?: '',
        ];
        return implode(' ', array_filter($parts));
    }

    private function servePostTripwireResponse(int $siteId, string $sessKey,
                                               string $systemType): never
    {
        // Serve a convincing fake "success" so they don't know the trap fired,
        // then the diversion engine handles all future requests
        $this->diversion->serveDecoy($siteId, $sessKey, 'GET', '/api/dashboard');
    }

    private function serveBannedResponse(int $siteId, string $sessKey,
                                         string $path): never
    {
        $this->diversion->serveDecoy($siteId, $sessKey, 'GET', $path);
    }

    private function logDefenses(array $stack, string $systemType,
                                 string $skillLevel, string $phase, int $severity): void
    {
        try {
            $db = Database::getInstance();
            $db->query(
                'INSERT INTO aegis_defense_log
                 (site_id, session_key, defenses_fired, system_type,
                  skill_level, phase, severity)
                 VALUES (?, ?, ?, ?, ?, ?, ?)',
                [
                    $this->siteId,
                    $this->tracker->getClientDetails()['session_key'],
                    json_encode($stack),
                    $systemType, $skillLevel, $phase, $severity,
                ]
            );
        } catch (\Throwable) {
            // Never let logging break the request
        }
    }
}
