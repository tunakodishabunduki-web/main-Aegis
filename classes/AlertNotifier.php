<?php
/**
 * AlertNotifier.php
 * Sends a WhatsApp message via Meta's official Cloud API when a
 * high-severity event fires.  Uses PHP's built-in cURL — no Guzzle
 * required, so it works in a plain SIMAP environment.
 */

namespace Aegis\Classes;

class AlertNotifier
{
    private int    $threshold;
    private string $recipient;
    private string $token;
    private string $phoneNumberId;

    /** Debounce: don't re-alert the same session within this many seconds */
    private const DEBOUNCE_SECONDS = 300;

    public function __construct()
    {
        $this->threshold     = (int) (getenv('HONEYPOT_ALERT_THRESHOLD')  ?: 50);
        $this->recipient     = getenv('HONEYPOT_ALERT_RECIPIENT')          ?: '255698741459';
        $this->token         = getenv('WHATSAPP_ACCESS_TOKEN')             ?: '';
        $this->phoneNumberId = getenv('WHATSAPP_PHONE_NUMBER_ID')          ?: '';
    }

    /**
     * Fires an alert if severity crosses the threshold and the session
     * has not already been alerted within the debounce window.
     */
    public function maybeAlert(
        int    $severity,
        string $sessionKey,
        array  $client,
        string $attackType,
        bool   $isBanned,
        ?string $enteredUsername = null,
        ?string $enteredPassword = null,
        ?string $endpoint        = null
    ): void {
        if ($severity < $this->threshold) return;
        if (!$this->isDebounced($sessionKey)) return;

        $message = $this->buildMessage(
            $severity, $client, $attackType, $isBanned,
            $enteredUsername, $enteredPassword, $endpoint
        );

        $this->sendWhatsApp($message);
        $this->markAlerted($sessionKey);

        // Trigger physical tracker on Critical severity (>=80)
        // Only fires if the tracker process is already running on a camera machine
        if ($severity >= 80) {
            $this->maybeActivateTracker([
                'ip'          => $client['ip'],
                'severity'    => $severity,
                'attack_type' => $attackType,
                'timestamp'   => date('c'),
            ]);
        }
    }

    /**
     * Signals the physical tracker process by writing the trigger flag file.
     * The tracker reads this on every frame — no HTTP call needed.
     * Never throws — a missing tracker never interrupts the main request.
     */
    private function maybeActivateTracker(array $attackerInfo): void
    {
        $scriptPath = dirname(__DIR__) . '/python/physical_tracker.py';
        $statusFile = '/tmp/aegis_tracker_status.json';

        if (!file_exists($scriptPath)) return;

        // Only signal if the tracker appears to be running (it writes its own status)
        if (file_exists($statusFile)) {
            $status = json_decode(file_get_contents($statusFile) ?: '{}', true) ?? [];
            if (!($status['running'] ?? false)) return;
        }

        $python  = getenv('AEGIS_PYTHON_BIN') ?: 'python3';
        $payload = escapeshellarg(json_encode($attackerInfo));
        // Run in background — never block the HTTP request
        $cmd = sprintf(
            '%s %s --trigger %s > /dev/null 2>&1 &',
            escapeshellcmd($python),
            escapeshellarg($scriptPath),
            $payload
        );
        shell_exec($cmd);
    }

    private function buildMessage(
        int    $severity,
        array  $client,
        string $attackType,
        bool   $isBanned,
        ?string $username,
        ?string $password,
        ?string $endpoint
    ): string {
        $lines = [
            'Boss Mmari njoo uku uone jinsi attacker anafanya uharibifu kwenye ghetto lako',
            '',
            '*Type:* ' . str_replace('_', ' ', $attackType),
            '*Severity:* ' . $severity . '%',
            '*IP:* ' . $client['ip'],
            '*Browser/OS:* ' . $client['browser'] . ' / ' . $client['os'],
            '*Endpoint:* ' . ($endpoint ?? 'n/a'),
        ];

        if ($username !== null) $lines[] = '*Username tried:* ' . $username;
        if ($password !== null) $lines[] = '*Password tried:* ' . $password;
        if ($isBanned)          $lines[] = "\nSession auto-banned.";

        return implode("\n", $lines);
    }

    private function sendWhatsApp(string $message): void
    {
        if (!$this->token || !$this->phoneNumberId) {
            error_log('[Aegis] WhatsApp alert skipped — missing env vars.');
            return;
        }

        $url     = "https://graph.facebook.com/v20.0/{$this->phoneNumberId}/messages";
        $payload = json_encode([
            'messaging_product' => 'whatsapp',
            'to'                => $this->recipient,
            'type'              => 'text',
            'text'              => ['body' => $message],
        ]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => [
                'Authorization: Bearer ' . $this->token,
                'Content-Type: application/json',
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            error_log('[Aegis] WhatsApp alert failed (' . $httpCode . '): ' . $response);
        }
    }

    /** Simple file-based debounce — swap for APCu/Redis in production */
    private function isDebounced(string $sessionKey): bool
    {
        $path = sys_get_temp_dir() . '/aegis_alert_' . $sessionKey;
        if (file_exists($path)) {
            $last = (int) file_get_contents($path);
            if ((time() - $last) < self::DEBOUNCE_SECONDS) return false;
        }
        return true;
    }

    private function markAlerted(string $sessionKey): void
    {
        file_put_contents(
            sys_get_temp_dir() . '/aegis_alert_' . $sessionKey,
            time()
        );
    }
}
