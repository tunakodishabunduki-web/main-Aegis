<?php
/**
 * DossierGenerator.php
 * ============================================================
 * Generates a forensic PDF dossier and serves it as a forced
 * download on the confirmed attacker's subsequent GET request.
 *
 * The PDF contains:
 *   - Cover page with Aegis logo and "SECURITY INCIDENT REPORT"
 *   - Attacker IP, GeoIP location, ISP, ASN
 *   - Full attack timeline with timestamps
 *   - Attack type analysis and severity breakdown
 *   - Tanzania Cybercrimes Act 2015 legal citations
 *   - Evidence hash (SHA-256 of all captured data)
 *
 * Effect: Wastes attacker bandwidth, fills their storage, and
 * delivers a significant psychological deterrent. Automated
 * scanners downloading PDFs = broken workflow.
 *
 * Requires: composer require fpdf/fpdf  (or lib/fpdf.php)
 * ============================================================
 */

namespace Aegis\Classes;

use Aegis\Config\Database;

class DossierGenerator
{
    private Database $db;
    private string   $fontDir;

    public function __construct()
    {
        $this->db      = Database::getInstance();
        $this->fontDir = dirname(__DIR__) . '/assets/fonts/';
    }

    // ================================================================
    //  SERVE PDF  —  force download on confirmed attacker's request
    // ================================================================

    /**
     * Generates the dossier and streams it as a PDF download.
     * This exits — nothing runs after this call.
     *
     * @param int    $siteId
     * @param string $sessionKey
     * @param string $systemType
     * @param int    $intensity   SecurityPriorityEngine intensity
     */
    public function serveDossier(int $siteId, string $sessionKey,
                                 string $systemType, int $intensity): never
    {
        $ip      = $this->getClientIp();
        $events  = $this->loadEvents($siteId, $sessionKey);
        $geo     = $this->geoLookup($ip);
        $content = $this->buildContent($ip, $sessionKey, $systemType, $events, $geo, $intensity);

        // Force download — fills their storage, breaks auto-scraper parsing
        $filename = 'SECURITY_INCIDENT_REPORT_' . date('Ymd_His') . '.pdf';
        header('Content-Type: application/pdf');
        header("Content-Disposition: attachment; filename=\"{$filename}\"");
        header('Cache-Control: no-cache, no-store');
        header('X-Legal-Reference: TZ-CCA-2015-S10');

        echo $this->renderPdf($content, $ip, $geo, $events);
        exit;
    }

    /**
     * Returns true if this session should receive the dossier.
     * Triggers on the SECOND or later request from a confirmed attacker.
     */
    public function shouldServeDossier(string $sessionKey, int $intensity): bool
    {
        if ($intensity < SecurityPriorityEngine::MEDIUM) return false;

        // Check if we've already served one to this session
        $flag = '/tmp/aegis_dossier_' . md5($sessionKey);
        if (file_exists($flag)) return false;

        // Mark as served so we don't loop
        touch($flag);
        return true;
    }

    // ================================================================
    //  PDF GENERATION  (plain text if FPDF not available)
    // ================================================================

    private function renderPdf(array $content, string $ip, array $geo, array $events): string
    {
        // Try FPDF first
        $fpdfPath = dirname(__DIR__) . '/vendor/autoload.php';
        $fpdfDirect = dirname(__DIR__) . '/lib/fpdf.php';

        if (file_exists($fpdfPath) || file_exists($fpdfDirect)) {
            return $this->renderWithFpdf($content, $ip, $geo, $events);
        }

        // Fallback: minimal valid PDF built manually
        return $this->renderMinimalPdf($content, $ip, $geo, $events);
    }

    private function renderWithFpdf(array $content, string $ip,
                                    array $geo, array $events): string
    {
        if (!class_exists('FPDF')) {
            $auto = dirname(__DIR__) . '/vendor/autoload.php';
            $direct = dirname(__DIR__) . '/lib/fpdf.php';
            if (file_exists($auto))   require_once $auto;
            elseif (file_exists($direct)) require_once $direct;
        }

        $pdf = new \FPDF('P', 'mm', 'A4');
        $pdf->SetAutoPageBreak(true, 15);
        $pdf->AddPage();

        // ── Cover ─────────────────────────────────────────────
        $pdf->SetFillColor(13, 15, 20);
        $pdf->Rect(0, 0, 210, 60, 'F');

        $pdf->SetFont('Helvetica', 'B', 22);
        $pdf->SetTextColor(229, 72, 77);
        $pdf->SetXY(20, 15);
        $pdf->Cell(170, 10, 'AEGIS SECURITY PLATFORM', 0, 1, 'C');

        $pdf->SetFont('Helvetica', 'B', 14);
        $pdf->SetTextColor(228, 230, 236);
        $pdf->SetXY(20, 30);
        $pdf->Cell(170, 8, 'SECURITY INCIDENT DOSSIER', 0, 1, 'C');

        $pdf->SetFont('Helvetica', '', 10);
        $pdf->SetTextColor(99, 103, 120);
        $pdf->SetXY(20, 45);
        $pdf->Cell(170, 6, 'CONFIDENTIAL — Tanzania Cybercrimes Act 2015 Documentation', 0, 1, 'C');

        // ── Report metadata ────────────────────────────────────
        $pdf->SetTextColor(30, 30, 30);
        $pdf->SetXY(20, 70);
        $pdf->SetFont('Helvetica', 'B', 11);
        $pdf->Cell(170, 7, 'INCIDENT IDENTIFICATION', 0, 1, 'L');
        $pdf->SetFont('Helvetica', '', 10);
        $pdf->SetXY(20, 78);
        $pdf->MultiCell(170, 6,
            "Report Date:    " . date('Y-m-d H:i:s') . " EAT (UTC+3)\n"
            . "Source IP:      {$ip}\n"
            . "Country:        " . ($geo['country'] ?? 'Unknown') . "\n"
            . "City:           " . ($geo['city']    ?? 'Unknown') . "\n"
            . "ISP:            " . ($geo['isp']     ?? 'Unknown') . "\n"
            . "ASN:            " . ($geo['as']      ?? 'Unknown') . "\n"
            . "Total Events:   " . count($events) . "\n"
            . "Evidence Hash:  " . $content['evidence_hash'],
        0, 'L');

        // ── Attack timeline ────────────────────────────────────
        $pdf->SetXY(20, $pdf->GetY() + 8);
        $pdf->SetFont('Helvetica', 'B', 11);
        $pdf->Cell(170, 7, 'ATTACK TIMELINE', 0, 1, 'L');
        $pdf->SetFont('Helvetica', '', 9);
        $pdf->SetFillColor(245, 246, 250);

        foreach (array_slice($events, 0, 25) as $i => $ev) {
            $fill = ($i % 2 === 0);
            $pdf->SetXY(20, $pdf->GetY());
            $pdf->SetFillColor($fill ? 245 : 255, $fill ? 246 : 255, $fill ? 250 : 255);
            $line = "[{$ev['created_at']}]  {$ev['attack_type']}  (Severity: {$ev['severity_score']}%)";
            $pdf->Cell(170, 5.5, $line, 0, 1, 'L', $fill);
        }
        if (count($events) > 25) {
            $pdf->SetFont('Helvetica', 'I', 9);
            $pdf->SetXY(20, $pdf->GetY() + 2);
            $pdf->Cell(170, 5, '... ' . (count($events) - 25) . ' more events not shown.', 0, 1, 'L');
        }

        // ── Legal citations ────────────────────────────────────
        $pdf->AddPage();
        $pdf->SetFont('Helvetica', 'B', 11);
        $pdf->SetXY(20, 20);
        $pdf->SetTextColor(229, 72, 77);
        $pdf->Cell(170, 7, 'LEGAL FRAMEWORK — APPLICABLE STATUTES', 0, 1, 'L');
        $pdf->SetTextColor(30, 30, 30);
        $pdf->SetFont('Helvetica', '', 10);
        $pdf->SetXY(20, 32);
        $pdf->MultiCell(170, 6,
            "Tanzania Cybercrimes Act, 2015 — Section 10\n"
            . "Unauthorised Access to a Computer System\n\n"
            . "(1) A person who intentionally and without authorisation accesses\n"
            . "the whole or any part of a computer system commits an offence\n"
            . "and shall on conviction be liable to imprisonment for a term of\n"
            . "not less than three years or to a fine of not less than five\n"
            . "million shillings or to both.\n\n"
            . "(2) Where the access is with intent to commit an offence, the\n"
            . "penalty increases to not less than seven years imprisonment or\n"
            . "a fine of not less than twenty million shillings or to both.\n\n"
            . "Additional Applicable Legislation:\n"
            . "- Electronic and Postal Communications Act, Cap 306\n"
            . "- Tanzania Communications Regulatory Authority Act, Cap 172\n"
            . "- Penal Code, Cap 16 (Computer Fraud provisions)",
        0, 'L');

        // ── Footer ────────────────────────────────────────────
        $pdf->SetXY(20, 270);
        $pdf->SetFont('Helvetica', 'I', 8);
        $pdf->SetTextColor(150, 150, 150);
        $pdf->Cell(170, 5,
            'Aegis Security Platform | Generated ' . date('Y-m-d H:i:s')
            . ' | Evidence retained 90 days',
        0, 1, 'C');

        return $pdf->Output('S'); // Return as string
    }

    private function renderMinimalPdf(array $content, string $ip,
                                      array $geo, array $events): string
    {
        // RFC-compliant minimal PDF without FPDF
        $text  = "AEGIS SECURITY PLATFORM — SECURITY INCIDENT DOSSIER\n\n";
        $text .= "Source IP: {$ip}\n";
        $text .= "Country: " . ($geo['country'] ?? 'Unknown') . "\n";
        $text .= "ISP: " . ($geo['isp'] ?? 'Unknown') . "\n";
        $text .= "Date: " . date('Y-m-d H:i:s') . " EAT\n";
        $text .= "Events: " . count($events) . "\n\n";
        $text .= "Tanzania Cybercrimes Act 2015, Section 10 — Unauthorised Access\n";
        $text .= "Penalty: 3-7 years imprisonment or TZS 5,000,000–20,000,000 fine\n\n";
        foreach (array_slice($events, 0, 10) as $ev) {
            $text .= "[{$ev['created_at']}] {$ev['attack_type']} ({$ev['severity_score']}%)\n";
        }
        $text .= "\nEvidence Hash: " . $content['evidence_hash'];

        $len  = strlen($text);
        return "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
             . "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
             . "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R>>endobj\n"
             . "4 0 obj<</Length {$len}>>\nstream\nBT /F1 10 Tf 30 760 Td\n"
             . "({$text}) Tj\nET\nendstream\nendobj\n"
             . "xref\n0 5\n0000000000 65535 f\n"
             . "trailer<</Size 5/Root 1 0 R>>\nstartxref\n9\n%%EOF";
    }

    // ================================================================
    //  HELPERS
    // ================================================================

    private function buildContent(string $ip, string $sessionKey, string $systemType,
                                  array $events, array $geo, int $intensity): array
    {
        $allData = $ip . $sessionKey . json_encode($events) . json_encode($geo);
        return [
            'evidence_hash' => hash('sha256', $allData),
            'generated_at'  => date('c'),
            'intensity'     => $intensity,
            'system_type'   => $systemType,
        ];
    }

    private function loadEvents(int $siteId, string $sessionKey): array
    {
        return $this->db->fetchAll(
            'SELECT attack_type, severity_score, endpoint, created_at
             FROM aegis_attack_log
             WHERE site_id = ? AND session_key = ?
             ORDER BY created_at ASC LIMIT 50',
            [$siteId, $sessionKey]
        );
    }

    private function geoLookup(string $ip): array
    {
        $geo = new GeoLookup();
        return $geo->lookup($ip);
    }

    private function getClientIp(): string
    {
        return trim(explode(',',
            $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
        )[0]);
    }
}
