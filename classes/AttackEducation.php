<?php
/**
 * AttackEducation.php
 * Plain-language knowledge base for every tracked attack type.
 * Used by the dashboard's Lessons Learned tab and the PDF appendix.
 */

namespace Aegis\Classes;

class AttackEducation
{
    private const KNOWLEDGE = [
        'FAILED_LOGIN' => [
            'title'         => 'Failed Login',
            'what_it_is'    => 'A wrong username/password. Normal alone — only a concern when it repeats rapidly.',
            'why_it_matters'=> 'Repeated failures against one account is the first step in credential-stuffing attacks.',
            'how_to_defend' => [
                'Never reveal whether the username or password was wrong.',
                'Track attempts per username AND per IP separately.',
                'Add CAPTCHA after 3-5 failures.'
            ],
            'learn_more'    => 'OWASP: Credential Stuffing Prevention Cheat Sheet',
        ],
        'BRUTE_FORCE' => [
            'title'         => 'Brute Force',
            'what_it_is'    => 'Automated repeated login attempts trying many password guesses quickly.',
            'why_it_matters'=> 'Weak or reused passwords fall to this eventually — it is a numbers game.',
            'how_to_defend' => [
                'Rate-limit login attempts (already in place).',
                'Lock accounts temporarily after N failures with exponential backoff.',
                'Require MFA on admin accounts specifically.'
            ],
            'learn_more'    => 'OWASP: Blocking Brute Force Attacks',
        ],
        'SQL_INJECTION_ATTEMPT' => [
            'title'         => 'SQL Injection',
            'what_it_is'    => "SQL syntax entered into a form field, hoping the backend builds a raw query from it.",
            'why_it_matters'=> 'Can expose or destroy an entire database in one request.',
            'how_to_defend' => [
                'Always use parameterized queries — never string-concatenate user input into SQL.',
                'Never grant your app\'s DB user more privileges than it needs.',
                'This detector is a logging aid — parameterized queries are your real defense.'
            ],
            'learn_more'    => 'OWASP Top 10: A03:2021 - Injection',
        ],
        'XSS_ATTEMPT' => [
            'title'         => 'Cross-Site Scripting (XSS)',
            'what_it_is'    => "A <script> tag or event handler submitted hoping your app renders it unescaped.",
            'why_it_matters'=> 'Can steal session cookies or run attacker-controlled JS in every victim\'s browser.',
            'how_to_defend' => [
                'Escape/encode all user content before rendering it in HTML.',
                'Use a Content-Security-Policy header.',
                'Use a templating engine that escapes by default.'
            ],
            'learn_more'    => 'OWASP Top 10: A03:2021 - Injection (XSS subtype)',
        ],
        'PATH_TRAVERSAL_ATTEMPT' => [
            'title'         => 'Path Traversal',
            'what_it_is'    => '../ sequences submitted hoping a file-reading endpoint steps outside its intended folder.',
            'why_it_matters'=> 'Can expose config files, source code, or credentials stored on the server filesystem.',
            'how_to_defend' => [
                'Never build file paths from raw user input.',
                'Validate resolved paths stay inside your intended base directory.',
                'Run your app process with minimal filesystem permissions.'
            ],
            'learn_more'    => 'OWASP: Path Traversal',
        ],
        'COMMAND_INJECTION_ATTEMPT' => [
            'title'         => 'OS Command Injection',
            'what_it_is'    => 'Shell syntax smuggled into input that might reach a system() or exec() call on your server.',
            'why_it_matters'=> 'If it works, the attacker runs arbitrary commands as your web process — most severe outcome possible.',
            'how_to_defend' => [
                'Avoid shelling out to user input entirely.',
                'If you must, use escapeshellarg() and never build the command from raw input.',
                'Run your server process with the least privilege possible.'
            ],
            'learn_more'    => 'OWASP: OS Command Injection Defense Cheat Sheet',
        ],
        'SSRF_ATTEMPT' => [
            'title'         => 'Server-Side Request Forgery (SSRF)',
            'what_it_is'    => 'Attacker supplies a URL (often cloud metadata endpoint) hoping your server fetches it on their behalf.',
            'why_it_matters'=> 'Can expose AWS credentials, internal services, or admin panels reachable only from inside your network.',
            'how_to_defend' => [
                'Validate outbound URLs against an allowlist of expected hosts.',
                'Block requests to private IP ranges and the cloud metadata endpoint at the network layer.'
            ],
            'learn_more'    => 'OWASP Top 10: A10:2021 - SSRF',
        ],
        'JWT_TAMPERING_ATTEMPT' => [
            'title'         => 'JWT Tampering',
            'what_it_is'    => 'A token with a modified or "none" algorithm header, trying to bypass signature verification.',
            'why_it_matters'=> 'If successful, lets an attacker forge a valid-looking session for any user, including admin.',
            'how_to_defend' => [
                'Always explicitly specify and verify the expected algorithm — never trust the alg field in the token itself.',
                'Use short-lived tokens with refresh rotation and a strong secret.'
            ],
            'learn_more'    => 'OWASP: JWT Security Cheat Sheet',
        ],
        'SCANNER_TOOL_DETECTED' => [
            'title'         => 'Automated Scanner Detected',
            'what_it_is'    => 'The User-Agent matched a known pen-testing or exploitation tool (sqlmap, nikto, Burp Suite, etc.).',
            'why_it_matters'=> 'Real browsers never identify themselves this way — strong signal of deliberate reconnaissance.',
            'how_to_defend' => [
                'Use as a priority signal, not a sole defense — sophisticated attackers spoof this header.',
                'A scanner signature plus a high-severity event elsewhere warrants immediate investigation.'
            ],
            'learn_more'    => 'Concept: User-Agent based reconnaissance detection',
        ],
        'THREAT_INTEL_IOC_MATCH' => [
            'title'         => 'Threat Intelligence IOC Match',
            'what_it_is'    => 'The requesting IP, domain, or hash matched a known indicator of compromise from threat intelligence feeds.',
            'why_it_matters'=> 'This IP or resource has been linked to known malicious activity in the broader threat landscape.',
            'how_to_defend' => [
                'Block the flagged IP at the firewall immediately.',
                'Investigate any prior access from this IP in your logs.',
                'Subscribe to updated threat intelligence feeds.'
            ],
            'learn_more'    => 'AlienVault OTX, Emerging Threats, URLhaus',
        ],
        'DECEPTION_HONEYTOKEN_TRIGGER' => [
            'title'         => 'Honeytoken Triggered',
            'what_it_is'    => 'A fake credential, API key, or file planted as a trap was accessed or used.',
            'why_it_matters'=> 'Honeytokens are never used by legitimate systems — any trigger is definitively malicious.',
            'how_to_defend' => [
                'This event should trigger immediate incident response.',
                'Rotate all real credentials that were near the honeytoken.',
                'Review all access logs for this session going back in time.'
            ],
            'learn_more'    => 'Concept: Honeytoken / Canary Token-based breach detection',
        ],
        'NETWORK_PORT_SCAN' => [
            'title'         => 'Network Port Scan Detected',
            'what_it_is'    => 'The source IP made connections to many ports in a short window — classic pre-attack reconnaissance.',
            'why_it_matters'=> 'Port scans map your attack surface and identify open services for targeting.',
            'how_to_defend' => [
                'Configure your firewall to drop, not reject, unexpected port connections.',
                'Enable port-scan detection rules in your IDS/IPS.',
                'Review which services are actually exposed and close unnecessary ones.'
            ],
            'learn_more'    => 'Concept: Network reconnaissance detection',
        ],
    ];

    /**
     * Returns the knowledge entry for a given attack type, or null.
     */
    public static function get(string $attackType): ?array
    {
        return self::KNOWLEDGE[$attackType] ?? null;
    }

    /**
     * Returns all lessons sorted by how frequently each type appears
     * in the provided event list — study evidence-first, not by textbook order.
     *
     * @param array $events  Rows with at least an 'attack_type' key.
     */
    public static function summarizeLessons(array $events): array
    {
        $counts = [];
        foreach ($events as $e) {
            $counts[$e['attack_type']] = ($counts[$e['attack_type']] ?? 0) + 1;
        }

        arsort($counts);

        $lessons = [];
        foreach ($counts as $type => $count) {
            $edu = self::get($type);
            if ($edu) {
                $lessons[] = array_merge($edu, ['attack_type' => $type, 'count' => $count]);
            }
        }
        return $lessons;
    }
}
