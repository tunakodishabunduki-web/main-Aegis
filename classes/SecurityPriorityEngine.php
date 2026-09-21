<?php
/**
 * SecurityPriorityEngine.php
 * ============================================================
 * The orchestration brain of Aegis. Given the system type,
 * attacker skill level, attack phase, and current severity,
 * it returns an ordered priority stack of which defenses to
 * apply — and at what intensity.
 *
 * Each connected site gets a different priority profile:
 *   - A payment / e-commerce system defends financial data
 *     with maximum aggression (scorched earth, ghost IDs,
 *     legal threats, dossier PDFs on every severe event)
 *   - A student portal uses lighter defenses (latency, 
 *     blackhole, poisoned grades) — legal threats are less
 *     appropriate for an academic context
 *   - A WiFi management system prioritises subscriber data
 *     protection and latency-based deterrence
 *
 * Intensity levels:
 *   OFF     — defense disabled for this system type
 *   LOW     — minimal response, minimal resource use
 *   MEDIUM  — standard honeypot behaviour
 *   HIGH    — aggressive deception + evidence collection
 *   MAXIMUM — full arsenal, all defenses active
 * ============================================================
 */

namespace Aegis\Classes;

class SecurityPriorityEngine
{
    // ── Defense identifiers ─────────────────────────────────────
    public const SCORCHED_EARTH   = 'SCORCHED_EARTH';    // decoy DB tripwire
    public const LATENCY_INJECT   = 'LATENCY_INJECT';    // adversarial delay
    public const POISON_CACHE     = 'POISON_CACHE';      // corrupted response data
    public const BLACKHOLE_SINK   = 'BLACKHOLE_SINK';    // fake 202 Accept
    public const GHOST_TRACKER    = 'GHOST_TRACKER';     // forensic ID breadcrumb
    public const LEGAL_THREAT     = 'LEGAL_THREAT';      // Tanzania CCA embedded
    public const DOSSIER_PDF      = 'DOSSIER_PDF';       // forensic PDF download
    public const TOXIC_JSON       = 'TOXIC_JSON';        // deeply nested crash payload

    // ── Intensity levels ────────────────────────────────────────
    public const OFF     = 0;
    public const LOW     = 1;
    public const MEDIUM  = 2;
    public const HIGH    = 3;
    public const MAXIMUM = 4;

    // ── Base priority matrix per system type ────────────────────
    // Each defense gets a base intensity for the system type.
    // This is then scaled by attacker skill + phase + severity.
    private const BASE_MATRIX = [
        'ECOMMERCE' => [
            self::SCORCHED_EARTH => self::MAXIMUM,
            self::LATENCY_INJECT => self::HIGH,
            self::POISON_CACHE   => self::HIGH,
            self::BLACKHOLE_SINK => self::MAXIMUM,
            self::GHOST_TRACKER  => self::MAXIMUM,
            self::LEGAL_THREAT   => self::MAXIMUM,
            self::DOSSIER_PDF    => self::HIGH,
            self::TOXIC_JSON     => self::HIGH,
        ],
        'SAAS' => [
            self::SCORCHED_EARTH => self::HIGH,
            self::LATENCY_INJECT => self::HIGH,
            self::POISON_CACHE   => self::HIGH,
            self::BLACKHOLE_SINK => self::MAXIMUM,
            self::GHOST_TRACKER  => self::MAXIMUM,
            self::LEGAL_THREAT   => self::HIGH,
            self::DOSSIER_PDF    => self::HIGH,
            self::TOXIC_JSON     => self::HIGH,
        ],
        'HEALTHCARE' => [
            self::SCORCHED_EARTH => self::MAXIMUM,
            self::LATENCY_INJECT => self::MEDIUM,
            self::POISON_CACHE   => self::HIGH,
            self::BLACKHOLE_SINK => self::HIGH,
            self::GHOST_TRACKER  => self::MAXIMUM,
            self::LEGAL_THREAT   => self::MAXIMUM,
            self::DOSSIER_PDF    => self::MAXIMUM,
            self::TOXIC_JSON     => self::MEDIUM,
        ],
        'WIFI_MANAGEMENT' => [
            self::SCORCHED_EARTH => self::HIGH,
            self::LATENCY_INJECT => self::HIGH,
            self::POISON_CACHE   => self::MEDIUM,
            self::BLACKHOLE_SINK => self::HIGH,
            self::GHOST_TRACKER  => self::HIGH,
            self::LEGAL_THREAT   => self::MEDIUM,
            self::DOSSIER_PDF    => self::MEDIUM,
            self::TOXIC_JSON     => self::LOW,
        ],
        'EDUCATION' => [
            self::SCORCHED_EARTH => self::HIGH,
            self::LATENCY_INJECT => self::LOW,
            self::POISON_CACHE   => self::MEDIUM,
            self::BLACKHOLE_SINK => self::HIGH,
            self::GHOST_TRACKER  => self::HIGH,
            self::LEGAL_THREAT   => self::MEDIUM,
            self::DOSSIER_PDF    => self::MEDIUM,
            self::TOXIC_JSON     => self::LOW,
        ],
        'AGENCY' => [
            self::SCORCHED_EARTH => self::MEDIUM,
            self::LATENCY_INJECT => self::MEDIUM,
            self::POISON_CACHE   => self::HIGH,
            self::BLACKHOLE_SINK => self::MEDIUM,
            self::GHOST_TRACKER  => self::HIGH,
            self::LEGAL_THREAT   => self::LOW,
            self::DOSSIER_PDF    => self::LOW,
            self::TOXIC_JSON     => self::LOW,
        ],
        'RESTAURANT' => [
            self::SCORCHED_EARTH => self::MEDIUM,
            self::LATENCY_INJECT => self::MEDIUM,
            self::POISON_CACHE   => self::MEDIUM,
            self::BLACKHOLE_SINK => self::HIGH,
            self::GHOST_TRACKER  => self::MEDIUM,
            self::LEGAL_THREAT   => self::LOW,
            self::DOSSIER_PDF    => self::LOW,
            self::TOXIC_JSON     => self::LOW,
        ],
        'PROPERTY' => [
            self::SCORCHED_EARTH => self::HIGH,
            self::LATENCY_INJECT => self::MEDIUM,
            self::POISON_CACHE   => self::HIGH,
            self::BLACKHOLE_SINK => self::HIGH,
            self::GHOST_TRACKER  => self::HIGH,
            self::LEGAL_THREAT   => self::MEDIUM,
            self::DOSSIER_PDF    => self::MEDIUM,
            self::TOXIC_JSON     => self::LOW,
        ],
        'GENERIC_BUSINESS' => [
            self::SCORCHED_EARTH => self::MEDIUM,
            self::LATENCY_INJECT => self::MEDIUM,
            self::POISON_CACHE   => self::MEDIUM,
            self::BLACKHOLE_SINK => self::MEDIUM,
            self::GHOST_TRACKER  => self::MEDIUM,
            self::LEGAL_THREAT   => self::LOW,
            self::DOSSIER_PDF    => self::LOW,
            self::TOXIC_JSON     => self::LOW,
        ],
    ];

    // ── Phase multipliers ───────────────────────────────────────
    // Later phases get more aggressive responses
    private const PHASE_MULTIPLIER = [
        'RECONNAISSANCE'    => 0.6,
        'CREDENTIAL_ATTACK' => 0.8,
        'INJECTION'         => 1.0,
        'ESCALATION'        => 1.2,
        'DESTRUCTION'       => 1.5,
    ];

    // ── Skill level multipliers ─────────────────────────────────
    // Advanced attackers get more sophisticated defenses
    private const SKILL_MULTIPLIER = [
        'SCRIPT_KIDDIE' => 0.7,
        'INTERMEDIATE'  => 1.0,
        'ADVANCED'      => 1.4,
    ];

    // ── Latency ranges per system type (ms) ────────────────────
    private const LATENCY_RANGES = [
        'ECOMMERCE'        => [300, 1500],
        'SAAS'             => [400, 1200],
        'HEALTHCARE'       => [200, 800],
        'WIFI_MANAGEMENT'  => [300, 1000],
        'EDUCATION'        => [100, 400],
        'AGENCY'           => [200, 600],
        'GENERIC_BUSINESS' => [150, 600],
    ];

    // ── Poison percentages per system type ─────────────────────
    // How much to corrupt numeric values (percentage)
    private const POISON_AMOUNTS = [
        'ECOMMERCE'        => ['tzs' => -8.5,  'usd' => 3.2,  'field' => 'amount'],
        'SAAS'             => ['tzs' => -5.0,  'usd' => 2.1,  'field' => 'usage'],
        'HEALTHCARE'       => ['tzs' => 0,     'usd' => 0,    'field' => 'results'], // corrupt lab values
        'WIFI_MANAGEMENT'  => ['tzs' => 12.0,  'usd' => 0,    'field' => 'bandwidth'],
        'EDUCATION'        => ['tzs' => 0,     'usd' => 0,    'field' => 'gpa'],    // corrupt GPA by -0.3
        'AGENCY'           => ['tzs' => -7.0,  'usd' => 5.5,  'field' => 'reach'],  // wrong analytics
        'GENERIC_BUSINESS' => ['tzs' => -5.0,  'usd' => 2.5,  'field' => 'total'],
    ];

    // ================================================================
    //  PUBLIC API
    // ================================================================

    /**
     * Returns the complete priority stack for this request context.
     * Each defense is returned with its resolved intensity level.
     * Stack is sorted highest-priority first.
     *
     * @return array<string, int>  ['DEFENSE_NAME' => intensity_level, ...]
     */
    public function getPriorityStack(
        string $systemType,
        string $skillLevel,
        string $phase,
        int    $severity
    ): array {
        $base    = self::BASE_MATRIX[$systemType] ?? self::BASE_MATRIX['GENERIC_BUSINESS'];
        $phaseMul= self::PHASE_MULTIPLIER[$phase]      ?? 1.0;
        $skillMul= self::SKILL_MULTIPLIER[$skillLevel]  ?? 1.0;
        $sevMul  = $this->severityMultiplier($severity);

        $stack = [];
        foreach ($base as $defense => $baseIntensity) {
            $resolved = (int) round($baseIntensity * $phaseMul * $skillMul * $sevMul);
            $resolved = min($resolved, self::MAXIMUM);
            $resolved = max($resolved, self::OFF);
            $stack[$defense] = $resolved;
        }

        // Sort highest intensity first for readability/logging
        arsort($stack);
        return $stack;
    }

    /**
     * Returns the specific intensity for one defense.
     */
    public function getIntensity(
        string $defense,
        string $systemType,
        string $skillLevel,
        string $phase,
        int    $severity
    ): int {
        $stack = $this->getPriorityStack($systemType, $skillLevel, $phase, $severity);
        return $stack[$defense] ?? self::OFF;
    }

    /**
     * Returns whether a specific defense should fire.
     * By default, defenses fire at intensity >= MEDIUM.
     */
    public function shouldActivate(
        string $defense,
        string $systemType,
        string $skillLevel,
        string $phase,
        int    $severity,
        int    $minIntensity = self::MEDIUM
    ): bool {
        return $this->getIntensity($defense, $systemType, $skillLevel, $phase, $severity)
            >= $minIntensity;
    }

    /**
     * Returns the latency delay in milliseconds for this request context.
     * Returns 0 if latency injection is OFF for this system.
     */
    public function getLatencyMs(
        string $systemType,
        string $skillLevel,
        string $phase,
        int    $severity
    ): int {
        $intensity = $this->getIntensity(
            self::LATENCY_INJECT, $systemType, $skillLevel, $phase, $severity
        );
        if ($intensity === self::OFF) return 0;

        $range  = self::LATENCY_RANGES[$systemType] ?? [150, 600];
        $base   = rand($range[0], $range[1]);

        // Scale by intensity: MAXIMUM = full range, LOW = 20% of range
        $scaled = (int) ($base * ($intensity / self::MAXIMUM));
        return max($scaled, 50);
    }

    /**
     * Returns the poison configuration for this system type.
     */
    public function getPoisonConfig(string $systemType): array
    {
        return self::POISON_AMOUNTS[$systemType] ?? self::POISON_AMOUNTS['GENERIC_BUSINESS'];
    }

    /**
     * Returns a human-readable summary of the priority stack.
     * Used in the dashboard and admin API.
     */
    public function summarise(
        string $systemType,
        string $skillLevel,
        string $phase,
        int    $severity
    ): array {
        $stack   = $this->getPriorityStack($systemType, $skillLevel, $phase, $severity);
        $labels  = [
            self::OFF     => 'OFF',
            self::LOW     => 'Low',
            self::MEDIUM  => 'Medium',
            self::HIGH    => 'High',
            self::MAXIMUM => 'Maximum',
        ];
        $named   = [];
        foreach ($stack as $defense => $intensity) {
            $named[] = [
                'defense'   => $defense,
                'intensity' => $intensity,
                'label'     => $labels[$intensity] ?? 'Unknown',
                'active'    => $intensity >= self::MEDIUM,
            ];
        }
        return [
            'system_type'   => $systemType,
            'skill_level'   => $skillLevel,
            'phase'         => $phase,
            'severity'      => $severity,
            'defenses'      => $named,
            'active_count'  => count(array_filter($named, fn($d) => $d['active'])),
        ];
    }

    // ================================================================
    //  PRIVATE
    // ================================================================

    private function severityMultiplier(int $severity): float
    {
        if ($severity >= 80) return 1.5;
        if ($severity >= 60) return 1.2;
        if ($severity >= 40) return 1.0;
        return 0.7;
    }
}
