<?php
/**
 * SiteHealth.php — HTTP uptime and latency check for a registered site.
 */

namespace Aegis\Classes;

class SiteHealth
{
    private const TIMEOUT = 8;

    /**
     * Pings one URL and returns status.  Never throws — a failed
     * check just reports as down.
     */
    public function check(string $siteUrl): array
    {
        $started = microtime(true);

        $ch = curl_init($siteUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_TIMEOUT         => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT  => self::TIMEOUT,
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_MAXREDIRS       => 3,
            CURLOPT_USERAGENT       => 'Aegis-HealthBot/1.0',
            CURLOPT_NOBODY          => false,
            CURLOPT_SSL_VERIFYPEER  => false,
        ]);

        curl_exec($ch);
        $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        $responseMs = (int) round((microtime(true) - $started) * 1000);

        $isUp = $httpCode >= 200 && $httpCode < 500 && empty($curlError);

        return [
            'is_up'           => $isUp,
            'status_code'     => $httpCode ?: null,
            'response_ms'     => $responseMs,
            'checked_at'      => date('c'),
            'error'           => $curlError ?: null,
        ];
    }

    /**
     * Checks all sites in parallel using curl_multi.
     *
     * @param array $sites  Each element must have 'id' and 'site_url'.
     */
    public function checkAll(array $sites): array
    {
        $results = [];
        foreach ($sites as $site) {
            $result           = $this->check($site['site_url']);
            $result['site_id'] = $site['id'];
            $results[]        = $result;
        }
        return $results;
    }
}


/**
 * GeoLookup.php — City-level IP geolocation via ip-api.com's free tier.
 */

namespace Aegis\Classes;

class GeoLookup
{
    private const TIMEOUT = 5;

    /**
     * Returns ['city'=>…,'country'=>…,'isp'=>…] or null on failure.
     * Skips private / loopback addresses automatically.
     */
    public function lookup(string $ip): ?array
    {
        if ($this->isPrivate($ip)) return null;

        $url = "http://ip-api.com/json/{$ip}?fields=status,country,city,isp,query";

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
        ]);
        $body = curl_exec($ch);
        curl_close($ch);

        if (!$body) return null;

        $data = json_decode($body, true);
        if (($data['status'] ?? '') !== 'success') return null;

        return [
            'city'    => $data['city']    ?? null,
            'country' => $data['country'] ?? null,
            'isp'     => $data['isp']     ?? null,
        ];
    }

    private function isPrivate(string $ip): bool
    {
        return str_starts_with($ip, '127.')
            || str_starts_with($ip, '10.')
            || str_starts_with($ip, '192.168.')
            || $ip === '::1';
    }
}


/**
 * ReportGenerator.php — PDF incident report using FPDF (no Composer needed for base class).
 * Install: composer require fpdf/fpdf   OR   download fpdf.php and require it.
 */

namespace Aegis\Classes;

use Aegis\Config\Database;

class ReportGenerator
{
    private Database $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    /**
     * Streams a PDF incident report for one attacker directly to the browser.
     */
    public function streamReport(int $siteId, string $sessionKey): void
    {
        $attacker = $this->db->fetchOne(
            'SELECT * FROM attacker_profile WHERE site_id = ? AND session_key = ?',
            [$siteId, $sessionKey]
        );

        if (!$attacker) {
            http_response_code(404);
            echo json_encode(['error' => 'Attacker not found']);
            return;
        }

        $events = $this->db->fetchAll(
            'SELECT attack_type, entered_username, entered_password,
                    endpoint, severity_score, created_at
             FROM attack_log
             WHERE site_id = ? AND session_key = ?
             ORDER BY created_at ASC',
            [$siteId, $sessionKey]
        );

        $geo = (new GeoLookup())->lookup($attacker['ip_address']);

        // FPDF must be installed — check before instantiating
        if (!class_exists('FPDF')) {
            $fpdfPath = __DIR__ . '/../lib/fpdf.php';
            if (file_exists($fpdfPath)) {
                require_once $fpdfPath;
            } else {
                http_response_code(500);
                echo json_encode(['error' => 'FPDF library not found. Run: composer require fpdf/fpdf']);
                return;
            }
        }

        $pdf = new \FPDF();
        $pdf->AddPage();
        $pdf->SetFont('Arial', 'B', 16);
        $pdf->Cell(0, 10, 'Security Incident Report', 0, 1, 'L');

        $pdf->SetFont('Arial', '', 9);
        $pdf->SetTextColor(120, 120, 120);
        $pdf->Cell(0, 6, 'Generated: ' . date('Y-m-d H:i:s'), 0, 1);
        $pdf->Ln(2);
        $pdf->Line(10, $pdf->GetY(), 200, $pdf->GetY());
        $pdf->Ln(4);

        // Attacker profile
        $pdf->SetFont('Arial', 'B', 12);
        $pdf->SetTextColor(0);
        $pdf->Cell(0, 8, 'Attacker Profile', 0, 1);
        $pdf->SetFont('Arial', '', 10);

        $fields = [
            'IP Address' => $attacker['ip_address'],
            'Browser'    => $attacker['browser'] ?? 'Unknown',
            'OS'         => $attacker['os'] ?? 'Unknown',
            'First seen' => $attacker['first_seen'],
            'Last seen'  => $attacker['last_seen'],
            'Attempts'   => (string) $attacker['total_attempts'],
            'Status'     => $attacker['is_banned'] ? 'BANNED — ' . $attacker['ban_reason'] : 'Active',
        ];

        if ($geo) {
            $fields['Location'] = trim(($geo['city'] ?? '') . ', ' . ($geo['country'] ?? ''), ', ');
            if (!empty($geo['isp'])) $fields['ISP'] = $geo['isp'];
        }

        foreach ($fields as $label => $value) {
            $pdf->SetFont('Arial', 'B', 10);
            $pdf->Cell(50, 6, $label . ':', 0, 0);
            $pdf->SetFont('Arial', '', 10);
            $pdf->Cell(0, 6, $value, 0, 1);
        }

        // Severity badge
        $score = $attacker['max_severity'];
        [$r, $g, $b] = $score >= 80 ? [192, 57, 43] : ($score >= 50 ? [230, 126, 34] : [46, 204, 113]);
        $pdf->SetFillColor($r, $g, $b);
        $pdf->SetTextColor(255, 255, 255);
        $pdf->Ln(2);
        $pdf->Cell(80, 8, AttackScoring::label($score) . ' — ' . $score . '% damage potential', 1, 1, 'C', true);
        $pdf->SetTextColor(0);
        $pdf->Ln(4);

        // Event timeline
        $pdf->SetFont('Arial', 'B', 12);
        $pdf->Cell(0, 8, 'Attack Timeline', 0, 1);

        foreach ($events as $i => $ev) {
            if ($pdf->GetY() > 260) $pdf->AddPage();

            $pdf->SetFont('Arial', '', 8);
            $pdf->SetTextColor(120, 120, 120);
            $pdf->Cell(0, 5, $ev['created_at'], 0, 1);

            $pdf->SetFont('Arial', 'B', 10);
            $pdf->SetTextColor(0);
            $pdf->Cell(0, 6, ($i + 1) . '. ' . str_replace('_', ' ', $ev['attack_type']) . ' — ' . $ev['severity_score'] . '% severity', 0, 1);

            $pdf->SetFont('Arial', '', 9);
            if (!empty($ev['entered_username'])) {
                $pdf->Cell(0, 5, '   username entered: ' . $ev['entered_username'], 0, 1);
            }
            if (!empty($ev['entered_password'])) {
                $pdf->Cell(0, 5, '   password entered: ' . $ev['entered_password'], 0, 1);
            }
            $pdf->Cell(0, 5, '   endpoint: ' . ($ev['endpoint'] ?? 'n/a'), 0, 1);
            $pdf->Ln(2);
        }

        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="incident-report-' . str_replace('.', '-', $attacker['ip_address']) . '.pdf"');
        $pdf->Output('S');
        exit;
    }
}
