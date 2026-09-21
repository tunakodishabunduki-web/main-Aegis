<?php
namespace Aegis\Classes;

class AttackerProfiler
{
    private const ADVANCED = [
        'SSRF_ATTEMPT','XXE_ATTEMPT','JWT_TAMPERING_ATTEMPT',
        'COMMAND_INJECTION_ATTEMPT','NOSQL_INJECTION_ATTEMPT',
        'SSTI_ATTEMPT','LDAP_INJECTION_ATTEMPT',
    ];
    private const INTERMEDIATE = [
        'SQL_INJECTION_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT',
        'OPEN_REDIRECT_ATTEMPT','PARAMETER_POLLUTION_ATTEMPT',
    ];
    private const KIDDIE = [
        'FAILED_LOGIN','BRUTE_FORCE','RATE_LIMIT_EXCEEDED',
        'SCANNER_TOOL_DETECTED','HONEYPOT_ROUTE_HIT',
    ];
    private const PHASES = [
        'RECONNAISSANCE'    => 'Mapping attack surface — scanning, enumerating',
        'CREDENTIAL_ATTACK' => 'Targeting authentication — brute force, stuffing',
        'INJECTION'         => 'Attempting data extraction or code execution',
        'ESCALATION'        => 'Trying to gain higher privileges or more data',
        'DESTRUCTION'       => 'Attempting to delete, corrupt, or exfiltrate data',
    ];

    public function classifySkillLevel(array $events): string
    {
        $types = array_column($events, 'attack_type');
        if (count(array_intersect($types, self::ADVANCED)) >= 1)     return 'ADVANCED';
        if (count(array_intersect($types, self::INTERMEDIATE)) >= 1) return 'INTERMEDIATE';
        return 'SCRIPT_KIDDIE';
    }

    public function detectPhase(array $events): string
    {
        if (empty($events)) return 'RECONNAISSANCE';
        $recent = array_column(array_slice($events, -5), 'attack_type');
        if (array_intersect($recent, ['DECOY_USER_DELETE_ATTEMPT','REAL_USER_DELETE_ATTEMPT'])) return 'DESTRUCTION';
        if (array_intersect($recent, ['DECOY_USER_VIEWED','UNAUTHORIZED_ADMIN_ACCESS']))        return 'ESCALATION';
        if (array_intersect($recent, array_merge(self::ADVANCED, self::INTERMEDIATE)))          return 'INJECTION';
        if (array_intersect($recent, ['BRUTE_FORCE','FAILED_LOGIN']))                           return 'CREDENTIAL_ATTACK';
        return 'RECONNAISSANCE';
    }

    public function summarise(array $events): array
    {
        $skill  = $this->classifySkillLevel($events);
        $phase  = $this->detectPhase($events);
        $total  = count($events);
        $counts = array_count_values(array_column($events, 'attack_type'));
        arsort($counts);
        $speed  = 'unknown';
        if ($total >= 2) {
            $first = strtotime($events[0]['created_at'] ?? 'now');
            $last  = strtotime($events[$total - 1]['created_at'] ?? 'now');
            $rate  = ($total / max($last - $first, 1)) * 60;
            $speed = $rate > 20 ? 'automated' : ($rate > 5 ? 'semi-automated' : 'manual');
        }
        return [
            'skill_level'       => $skill,
            'phase'             => $phase,
            'phase_description' => self::PHASES[$phase] ?? '',
            'total_events'      => $total,
            'attack_speed'      => $speed,
            'top_attacks'       => array_slice(array_keys($counts), 0, 3),
            'deception_level'   => match ($skill) {
                'ADVANCED'      => 'HIGH',
                'INTERMEDIATE'  => 'MEDIUM',
                default         => 'LOW',
            },
        ];
    }

    public function predictNextTarget(array $events, string $systemType): array
    {
        return match ($this->detectPhase($events)) {
            'RECONNAISSANCE'    => ['/api/users', '/api/admin', '/api/config'],
            'CREDENTIAL_ATTACK' => ['/api/login', '/api/auth', '/api/admin/login'],
            'INJECTION'         => ['/api/users', '/api/orders', '/api/search'],
            'ESCALATION'        => ['/api/admin/users', '/api/admin/settings'],
            'DESTRUCTION'       => ['/api/admin/users/1', '/api/admin/delete'],
            default             => ['/api/dashboard'],
        };
    }
}
