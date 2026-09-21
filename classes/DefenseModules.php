<?php
/**
 * DefenseModules.php
 * ============================================================
 * Three lightweight defense modules that don't warrant
 * their own files:
 *
 * LatencyInjector   — Adversarial delay injection
 *   Checks ASN/IP for cloud providers, Tor, VPN ranges.
 *   Injects randomised delay so automated retry logic breaks.
 *   Delay is random — looks like network packet loss to scanners.
 *
 * BlackholeSink     — Fake 202 Accept for POST/DELETE floods
 *   Returns HTTP 202 Accepted with a fake transaction ID.
 *   Attacker's flood scripts think they succeeded.
 *   Real DB never touched. Real Rust/PHP engine stays idle.
 *
 * ToxicJson         — Deeply nested crash payload
 *   Serves JSON nested 1500 levels deep alongside fake data.
 *   Python json.loads → RecursionError.
 *   PHP json_decode  → returns null (silent fail).
 *   Node JSON.parse  → Maximum call stack exceeded.
 *   Only served to CONFIRMED attackers (severity ≥ 80).
 * ============================================================
 */

namespace Aegis\Classes;

// ================================================================
// 1. LATENCY INJECTOR
// ================================================================

class LatencyInjector
{
    // Known cloud provider / scanner IP ranges (CIDR — simplified)
    private const CLOUD_RANGES = [
        // AWS
        '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.0.0.0/8',
        '35.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8',
        // GCP
        '8.34.208.0/20', '34.64.0.0/10', '35.184.0.0/13',
        // Azure
        '20.0.0.0/8', '40.0.0.0/8',
        // DigitalOcean
        '104.131.0.0/16', '104.236.0.0/16', '138.197.0.0/16',
        // Hetzner
        '78.46.0.0/15', '88.198.0.0/16', '95.216.0.0/16',
        // Linode
        '45.33.0.0/17', '45.56.0.0/21', '45.79.0.0/16',
    ];

    // Known Tor exit node ranges (partial — full list via threat_intelligence.py)
    private const TOR_PREFIXES = [
        '176.10.', '185.220.', '198.96.', '51.75.', '62.102.',
    ];

    // VPN provider ranges (partial)
    private const VPN_PREFIXES = [
        '217.138.', '185.159.', '156.146.', '86.106.',
    ];

    /**
     * Injects delay if the source looks hostile.
     * Call at the start of every request in Middleware.
     *
     * @param int $intensityLevel  From SecurityPriorityEngine
     * @param int $overrideMs      Force a specific delay (0 = auto)
     */
    public function maybeDelay(int $intensityLevel, int $overrideMs = 0): void
    {
        if ($intensityLevel === SecurityPriorityEngine::OFF) return;

        $ip = $this->getClientIp();

        // Check if source is from a suspicious network
        $isSuspicious = $this->isCloudIp($ip)
                     || $this->isTorExit($ip)
                     || $this->isVpn($ip);

        // Authenticated with a valid API key — skip delay
        $hasValidKey = !empty($_SERVER['HTTP_AUTHORIZATION'])
            && strlen($_SERVER['HTTP_AUTHORIZATION']) > 40;

        if (!$isSuspicious && $hasValidKey) return;

        // Calculate delay
        if ($overrideMs > 0) {
            $delay = $overrideMs;
        } else {
            $delay = $this->calculateDelay($intensityLevel, $isSuspicious);
        }

        if ($delay > 0) {
            usleep($delay * 1000); // convert ms to μs
        }
    }

    /**
     * Injects delay for a confirmed attacker (already in the DB).
     * Higher delays than for suspicious-but-unconfirmed IPs.
     */
    public function delayAttacker(int $severity, string $systemType,
                                  string $phase, int $intensityLevel): void
    {
        $engine   = new SecurityPriorityEngine();
        $delayMs  = $engine->getLatencyMs($systemType, 'INTERMEDIATE', $phase, $severity);

        // Randomise to defeat retry logic — looks like real network jitter
        $jitter  = rand(-80, 120);
        $final   = max(0, $delayMs + $jitter);

        if ($final > 0) usleep($final * 1000);
    }

    private function calculateDelay(int $intensity, bool $isSuspicious): int
    {
        $base = match ($intensity) {
            SecurityPriorityEngine::LOW     => rand(50,  200),
            SecurityPriorityEngine::MEDIUM  => rand(150, 450),
            SecurityPriorityEngine::HIGH    => rand(300, 900),
            SecurityPriorityEngine::MAXIMUM => rand(500, 1500),
            default                         => 0,
        };
        // Additional penalty for confirmed cloud/VPN/Tor IPs
        return $isSuspicious ? $base + rand(100, 400) : $base;
    }

    private function isCloudIp(string $ip): bool
    {
        $long = ip2long($ip);
        if ($long === false) return false;
        foreach (self::CLOUD_RANGES as $cidr) {
            [$range, $bits] = explode('/', $cidr);
            $mask = ~((1 << (32 - (int)$bits)) - 1);
            if ((ip2long($range) & $mask) === ($long & $mask)) return true;
        }
        return false;
    }

    private function isTorExit(string $ip): bool
    {
        foreach (self::TOR_PREFIXES as $prefix) {
            if (str_starts_with($ip, $prefix)) return true;
        }
        return false;
    }

    private function isVpn(string $ip): bool
    {
        foreach (self::VPN_PREFIXES as $prefix) {
            if (str_starts_with($ip, $prefix)) return true;
        }
        return false;
    }

    private function getClientIp(): string
    {
        return trim(explode(',',
            $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
        )[0]);
    }
}


// ================================================================
// 2. BLACKHOLE SINK
// ================================================================

class BlackholeSink
{
    private const FAKE_PREFIXES = [
        'txn_',
        'ord_',
        'pay_',
        'inv_',
        'ref_',
        'trx_',
    ];

    /**
     * Returns true if this request should be blackholed.
     * Only applies to POST / PUT / DELETE from confirmed attackers.
     */
    public function shouldBlackhole(string $method, int $severity,
                                    int $intensityLevel): bool
    {
        if ($intensityLevel < SecurityPriorityEngine::MEDIUM) return false;
        if (!in_array(strtoupper($method), ['POST','PUT','DELETE','PATCH'])) return false;
        return $severity >= 70;
    }

    /**
     * Serves the blackhole response and exits.
     * Returns HTTP 202 Accepted with a fake transaction ID.
     * Never touches the real DB.
     */
    public function serve(string $method, string $path): never
    {
        $fakeId = $this->generateFakeId();

        http_response_code(202);
        header('Content-Type: application/json');

        $response = match (strtoupper($method)) {
            'POST'   => ['accepted' => true, 'id' => $fakeId, 'status' => 'processing',
                         'message' => 'Request received and queued for processing'],
            'DELETE' => ['accepted' => true, 'deleted' => true, 'id' => $fakeId,
                         'message' => 'Delete request queued'],
            'PUT',
            'PATCH'  => ['accepted' => true, 'updated' => true, 'id' => $fakeId,
                         'message' => 'Update queued'],
            default  => ['accepted' => true, 'id' => $fakeId],
        };

        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    private function generateFakeId(): string
    {
        $prefix = self::FAKE_PREFIXES[array_rand(self::FAKE_PREFIXES)];
        return $prefix . bin2hex(random_bytes(12));
    }
}


// ================================================================
// 3. TOXIC JSON
// ================================================================

class ToxicJson
{
    // Nesting depth — enough to crash most poorly-written parsers
    // without being so large it saturates our own bandwidth
    private const NEST_DEPTH = 1500;

    /**
     * Returns true if toxic JSON should be mixed into this response.
     * Only for CONFIRMED attackers (severity >= 80) at HIGH+ intensity.
     */
    public function shouldPoison(int $severity, int $intensityLevel,
                                 string $skillLevel): bool
    {
        if ($intensityLevel < SecurityPriorityEngine::HIGH) return false;
        if ($severity < 80)                                 return false;
        // Only apply to intermediate+ attackers — script kiddies
        // probably won't even parse the JSON properly anyway
        return in_array($skillLevel, ['INTERMEDIATE', 'ADVANCED']);
    }

    /**
     * Returns the deeply-nested structure to merge into a response.
     *
     * The nesting is iterative (not recursive) in PHP so OUR
     * server doesn't crash generating it. The attacker's parser
     * however uses the naive recursive approach and will either:
     *   - Python: raise RecursionError (sys.setrecursionlimit default 1000)
     *   - PHP:    return null from json_decode
     *   - Node:   Maximum call stack exceeded
     *   - Ruby:   SystemStackError
     */
    public function generatePayload(): array
    {
        // Build 1500-level deep nesting iteratively
        $inner = ['_t' => time()]; // small real payload at the deepest level
        for ($i = 0; $i < self::NEST_DEPTH; $i++) {
            $inner = ['_n' => $i, '_d' => $inner];
        }

        return [
            '_debug'  => $inner,         // named _debug — looks like leaked internals
            '_schema' => $this->fakeSchemaBlob(),
        ];
    }

    /**
     * Merges toxic payload into an existing response array.
     * The top-level keys of the real data are preserved —
     * the poison sits in the _debug and _schema keys.
     */
    public function inject(array $response): array
    {
        return array_merge($response, $this->generatePayload());
    }

    /**
     * Generates a large schema blob that looks like a leaked
     * internal API definition — more attractive to parse.
     */
    private function fakeSchemaBlob(): array
    {
        return [
            'version'    => '3.0.0',
            'endpoints'  => array_fill(0, 50, [
                'path'   => '/api/v1/internal/' . bin2hex(random_bytes(4)),
                'method' => 'POST',
                'auth'   => 'ADMIN_ONLY',
            ]),
            'secret_keys'=> array_fill(0, 20, 'sk_live_' . bin2hex(random_bytes(16))),
        ];
    }
}
