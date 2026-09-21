<?php
/**
 * AttackScoring.php
 * Translates attack type strings into an explainable 0-100 severity score.
 * Severity is a function of how close the action came to actually harming
 * real data — not an arbitrary number.
 */

namespace Aegis\Classes;

class AttackScoring
{
    /** Base severity for each known attack type */
    private const WEIGHTS = [
        'FAILED_LOGIN'                 => 10,
        'BRUTE_FORCE'                  => 35,
        'SQL_INJECTION_ATTEMPT'        => 55,
        'XSS_ATTEMPT'                  => 45,
        'CSRF_TOKEN_MISSING'           => 25,
        'HONEYPOT_ROUTE_HIT'           => 40,
        'UNAUTHORIZED_ADMIN_ACCESS'    => 60,
        'DECOY_USER_VIEWED'            => 50,
        'DECOY_USER_DELETE_ATTEMPT'    => 90,
        'REAL_USER_DELETE_ATTEMPT'     => 100,
        'RATE_LIMIT_EXCEEDED'          => 20,
        'PATH_TRAVERSAL_ATTEMPT'       => 60,
        'COMMAND_INJECTION_ATTEMPT'    => 85,
        'XXE_ATTEMPT'                  => 65,
        'OPEN_REDIRECT_ATTEMPT'        => 30,
        'SSRF_ATTEMPT'                 => 70,
        'NOSQL_INJECTION_ATTEMPT'      => 55,
        'JWT_TAMPERING_ATTEMPT'        => 75,
        'PARAMETER_POLLUTION_ATTEMPT'  => 35,
        'SCANNER_TOOL_DETECTED'        => 45,
        // Python module detections
        'THREAT_INTEL_IOC_MATCH'       => 80,
        'DECEPTION_HONEYTOKEN_TRIGGER' => 90,
        'NETWORK_PORT_SCAN'            => 50,
        'NETWORK_DNS_ANOMALY'          => 55,
    ];

    /**
     * Score a single event.
     */
    public static function scoreEvent(string $attackType): int
    {
        return self::WEIGHTS[$attackType] ?? 15;
    }

    /**
     * Score a session: takes the highest prior event, adds a persistence
     * bonus for repeated attempts, caps at 100.
     *
     * @param array  $priorEvents   Array of rows with at least 'attack_type' key
     * @param string $newAttackType
     */
    public static function scoreSession(array $priorEvents, string $newAttackType): int
    {
        $base = self::scoreEvent($newAttackType);

        $priorMax = 0;
        foreach ($priorEvents as $event) {
            $s = self::scoreEvent($event['attack_type']);
            if ($s > $priorMax) {
                $priorMax = $s;
            }
        }

        $persistenceBonus = min(count($priorEvents) * 2, 20);

        return min(100, max($base, $priorMax) + $persistenceBonus);
    }

    /**
     * Returns a human-readable severity label for a score.
     */
    public static function label(int $score): string
    {
        if ($score >= 80) return 'Critical';
        if ($score >= 50) return 'High';
        if ($score >= 25) return 'Moderate';
        return 'Low';
    }
}
