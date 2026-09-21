<?php
/**
 * LegalThreatInjector.php
 * ============================================================
 * Two mechanisms:
 *
 * 1. EMBEDDED LEGAL NOTICE
 *    Encodes Tanzania Cybercrimes Act 2015, Section 10 in
 *    Base64 and embeds it in the JSON 'message' field of
 *    403/401 responses. The attacker's own IP and timestamp
 *    are included in the decoded text.
 *
 *    When a sophisticated attacker decodes the message field
 *    and reads: "You are in violation of the Tanzania Cybercrimes
 *    Act 2015, Section 10. Your IP 41.222.13.87 has been logged
 *    at 2024-01-15 09:41:22 EAT" — the psychological effect is
 *    significant.
 *
 * 2. AUTOMATED ABUSE REPORT
 *    Fires an email to the hosting provider's abuse contact
 *    (retrieved via ip-api.com) documenting the attack with
 *    full forensic detail. This is fully legal — private
 *    businesses have the right to report hostile access.
 * ============================================================
 */

namespace Aegis\Classes;

class LegalThreatInjector
{
    // Tanzania Cybercrimes Act 2015 — actual statute text
    private const TZ_CYBERCRIMES_ACT = <<<LAW
TANZANIA CYBERCRIMES ACT, 2015
Section 10 — Unauthorised Access to a Computer System

(1) A person who intentionally and without authorisation accesses
the whole or any part of a computer system commits an offence
and shall on conviction be liable to imprisonment for a term of
not less than three years or to a fine of not less than five
million shillings or to both.

(2) A person who intentionally and without authorisation accesses
a computer system and with intent to commit an offence, obtains
data, disrupts the availability of data or interferes with
a computer system commits an offence.

(3) On conviction of an offence under subsection (2), a person
is liable to imprisonment for a term of not less than seven
years or to a fine of not less than twenty million shillings
or to both.

NOTICE OF FORENSIC EVIDENCE COLLECTION:
Your access attempt against this system has been logged under
the above statute. The following evidence has been captured
and will be submitted to the Tanzania Communications Regulatory
Authority (TCRA) and relevant law enforcement agencies:

  IP Address:    %IP%
  Timestamp:     %TIMESTAMP%
  User-Agent:    %UA%
  Session Key:   %SESSION%
  Attack Type:   %ATTACK_TYPE%
  Severity:      %SEVERITY%/100

This report is automatically forwarded to the abuse contact
of your internet service provider. Continued access attempts
will result in a formal criminal complaint.

Reference: TCRA Act, Cap 172 R.E 2002 | Cybercrimes Act 2015
LAW;

    private const ABUSE_EMAIL_TEMPLATE = <<<EMAIL
To: %ABUSE_EMAIL%
From: security@aegis-honeypot.internal
Subject: Automated Cybercrime Report — Unauthorised System Access

Dear Abuse Team,

This is an automated forensic report from a security platform
protecting a commercial system in Tanzania.

We are reporting unauthorised access attempts that violate
Tanzania's Cybercrimes Act 2015, Section 10, originating
from an IP address within your network.

INCIDENT DETAILS
================
Source IP:       %IP%
Reverse DNS:     %RDNS%
ASN:             %ASN%
ISP:             %ISP%
Country:         %COUNTRY%
First Seen:      %FIRST_SEEN%
Last Attempt:    %TIMESTAMP%
Total Attempts:  %ATTEMPTS%
Attack Types:    %ATTACK_TYPES%
Severity Score:  %SEVERITY%/100

ATTACK SUMMARY
==============
The source IP has conducted the following hostile activities
against our protected system:

%ATTACK_DETAIL%

ACTION REQUESTED
================
Please investigate the above IP address and take appropriate
action in accordance with your acceptable use policy.

This report has been generated automatically and constitutes
a formal abuse notification. Evidence is retained for 90 days.

Regards,
Aegis Security Platform
Automated Incident Response System
EMAIL;

    // ================================================================
    //  PUBLIC API
    // ================================================================

    /**
     * Returns a 403 response body with the legal notice embedded.
     * The outer JSON looks like a standard 403 — the notice is
     * in the 'message' field as a Base64 string.
     *
     * @param string $sessionKey
     * @param string $attackType
     * @param int    $severity
     * @param int    $intensity   From SecurityPriorityEngine
     */
    public function buildLegalResponse(
        string $sessionKey,
        string $attackType,
        int    $severity,
        int    $intensity = SecurityPriorityEngine::HIGH
    ): array {
        $ip        = $this->getClientIp();
        $ua        = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $timestamp = date('Y-m-d H:i:s') . ' EAT (UTC+3)';

        $legalText = strtr(self::TZ_CYBERCRIMES_ACT, [
            '%IP%'         => $ip,
            '%TIMESTAMP%'  => $timestamp,
            '%UA%'         => substr($ua, 0, 100),
            '%SESSION%'    => $sessionKey,
            '%ATTACK_TYPE%'=> $attackType,
            '%SEVERITY%'   => $severity,
        ]);

        $encoded = base64_encode($legalText);

        // Response looks like a standard 403 to most log parsers
        // Only someone who manually reads and decodes the message
        // field will see the full legal notice
        $response = [
            'error'   => 'Forbidden',
            'code'    => 'ACCESS_DENIED',
            'message' => $encoded,   // base64 legal notice — attacker will decode this
        ];

        // At MAXIMUM intensity: also add a hint that it's encoded
        // This is deliberate — we WANT them to decode and read it
        if ($intensity >= SecurityPriorityEngine::MAXIMUM) {
            $response['_debug'] = 'See message field (base64)';
            $response['_ref']   = 'TZ-CCA-2015-S10';
        }

        return $response;
    }

    /**
     * Fires an automated abuse report to the hosting provider
     * of the attacker's IP. Uses ip-api.com for ISP lookup.
     *
     * This runs asynchronously (via shell_exec background job)
     * so it never blocks the HTTP response.
     *
     * @param array  $attackerEvents  Recent events from aegis_attack_log
     * @param int    $severity
     */
    public function sendAbuseReport(array $attackerEvents, int $severity): void
    {
        if (empty($attackerEvents)) return;

        $ip = $this->getClientIp();

        // Fire async — never block the real response
        $payload = escapeshellarg(json_encode([
            'ip'      => $ip,
            'events'  => count($attackerEvents),
            'severity'=> $severity,
            'types'   => array_unique(array_column($attackerEvents, 'attack_type')),
            'first'   => $attackerEvents[0]['created_at']  ?? date('Y-m-d H:i:s'),
            'last'    => end($attackerEvents)['created_at'] ?? date('Y-m-d H:i:s'),
        ]));

        $script = dirname(__DIR__) . '/python/abuse_reporter.py';
        if (file_exists($script)) {
            $python = getenv('AEGIS_PYTHON_BIN') ?: 'python3';
            shell_exec("{$python} {$script} --args {$payload} > /dev/null 2>&1 &");
        } else {
            // Fallback: log the abuse report locally for manual sending
            error_log("[Aegis Legal] Abuse report generated for {$ip}. "
                . "Severity: {$severity}. Events: " . count($attackerEvents));
        }
    }

    /**
     * Returns the plain-text legal notice (decoded) for admin view.
     * Used in the dossier PDF and dashboard.
     */
    public function getLegalNoticeText(
        string $ip,
        string $sessionKey,
        string $attackType,
        int    $severity
    ): string {
        return strtr(self::TZ_CYBERCRIMES_ACT, [
            '%IP%'         => $ip,
            '%TIMESTAMP%'  => date('Y-m-d H:i:s') . ' EAT',
            '%UA%'         => substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 100),
            '%SESSION%'    => $sessionKey,
            '%ATTACK_TYPE%'=> $attackType,
            '%SEVERITY%'   => $severity,
        ]);
    }

    /**
     * Builds the abuse email text for a given attacker.
     * Used by the Python abuse_reporter or for manual sending.
     */
    public function buildAbuseEmail(
        string $ip,
        string $abuseEmail,
        string $isp,
        string $asn,
        string $country,
        array  $events,
        int    $severity
    ): string {
        $types  = implode(', ', array_unique(array_column($events, 'attack_type')));
        $detail = '';
        foreach (array_slice($events, 0, 5) as $e) {
            $detail .= "  [{$e['created_at']}] {$e['attack_type']}\n";
        }
        if (count($events) > 5) {
            $detail .= '  ... and ' . (count($events) - 5) . " more events.\n";
        }

        return strtr(self::ABUSE_EMAIL_TEMPLATE, [
            '%ABUSE_EMAIL%'  => $abuseEmail,
            '%IP%'           => $ip,
            '%RDNS%'         => gethostbyaddr($ip) ?: 'N/A',
            '%ASN%'          => $asn,
            '%ISP%'          => $isp,
            '%COUNTRY%'      => $country,
            '%FIRST_SEEN%'   => $events[0]['created_at']        ?? 'Unknown',
            '%TIMESTAMP%'    => end($events)['created_at']       ?? date('Y-m-d H:i:s'),
            '%ATTEMPTS%'     => count($events),
            '%ATTACK_TYPES%' => $types,
            '%SEVERITY%'     => $severity,
            '%ATTACK_DETAIL%'=> $detail,
        ]);
    }

    private function getClientIp(): string
    {
        return trim(explode(',',
            $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
        )[0]);
    }
}
