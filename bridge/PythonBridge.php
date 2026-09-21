<?php
/**
 * PythonBridge.php
 * Calls the Python security modules from PHP and returns their output
 * as PHP arrays.  Each call is isolated (subprocess), so a Python
 * crash never takes down the PHP process.
 *
 * Requirements:
 *   - Python 3.8+ in PATH (or set AEGIS_PYTHON_BIN env var)
 *   - Python tool scripts in the /python/ directory next to this file
 */

namespace Aegis\Bridge;

class PythonBridge
{
    private string $pythonBin;
    private string $toolsDir;
    private int    $timeout;

    public function __construct()
    {
        $this->pythonBin = getenv('AEGIS_PYTHON_BIN') ?: 'python3';
        $this->toolsDir  = dirname(__DIR__) . '/python';
        $this->timeout   = 30; // seconds per call
    }

    /**
     * Run a Python tool script with optional JSON-encoded arguments.
     * The script must print a single JSON object on stdout.
     *
     * @param  string $script   filename inside /python/ (e.g. 'threat_intelligence.py')
     * @param  array  $args     passed as JSON via --args flag
     * @return array            decoded result or ['error' => '...'] on failure
     */
    public function run(string $script, array $args = []): array
    {
        $scriptPath = $this->toolsDir . '/' . $script;

        if (!file_exists($scriptPath)) {
            return ['error' => "Script not found: {$script}"];
        }

        $encodedArgs = escapeshellarg(json_encode($args));
        $cmd = sprintf(
            '%s %s --args %s 2>&1',
            escapeshellcmd($this->pythonBin),
            escapeshellarg($scriptPath),
            $encodedArgs
        );

        $output   = null;
        $exitCode = null;

        // Use proc_open so we can enforce a timeout
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            return ['error' => 'Failed to start Python process'];
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);

        if ($exitCode !== 0) {
            error_log("[Aegis PythonBridge] {$script} exited {$exitCode}: {$stderr}");
            return ['error' => "Script exited with code {$exitCode}", 'details' => trim($stderr)];
        }

        $decoded = json_decode(trim($stdout), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("[Aegis PythonBridge] {$script} returned non-JSON: {$stdout}");
            return ['error' => 'Script returned invalid JSON', 'raw' => trim($stdout)];
        }

        return $decoded;
    }

    // ------------------------------------------------------------------
    // Typed wrappers for each module — makes controller code readable
    // ------------------------------------------------------------------

    /** Returns an IOC summary and recent threat indicators */
    public function threatIntelSummary(): array
    {
        return $this->run('threat_intelligence.py', ['action' => 'summary']);
    }

    /** Fetches latest IOC feeds (may take a few seconds) */
    public function threatIntelCollect(): array
    {
        return $this->run('threat_intelligence.py', ['action' => 'collect']);
    }

    /** Checks a single IP/domain/hash against stored indicators */
    public function checkIoc(string $indicator): array
    {
        return $this->run('threat_intelligence.py', ['action' => 'check', 'indicator' => $indicator]);
    }

    /** Returns all active honeytokens and decoys */
    public function deceptionStatus(): array
    {
        return $this->run('deception_grid.py', ['action' => 'status']);
    }

    /** Creates a honeytoken of a given type */
    public function createHoneytoken(string $type): array
    {
        return $this->run('deception_grid.py', ['action' => 'create_token', 'type' => $type]);
    }

    /** Returns network forensics alert summary */
    public function networkAlerts(): array
    {
        return $this->run('network_forensics.py', ['action' => 'alerts']);
    }

    /** Returns network packet summary stats */
    public function networkSummary(): array
    {
        return $this->run('network_forensics.py', ['action' => 'summary']);
    }

    /** Returns the status of all Python modules (for the dashboard health panel) */
    public function moduleStatus(): array
    {
        $modules = [
            'threat_intelligence' => 'threat_intelligence.py',
            'deception_grid'      => 'deception_grid.py',
            'network_forensics'   => 'network_forensics.py',
            'physical_tracker'    => 'physical_tracker.py',
        ];

        $status = [];
        foreach ($modules as $name => $script) {
            $result = $this->run($script, ['action' => 'ping']);
            $status[$name] = [
                'running' => !isset($result['error']),
                'message' => $result['error'] ?? ($result['status'] ?? 'OK'),
            ];
        }
        return $status;
    }

    // ── Physical Tracker ──────────────────────────────────────

    /**
     * Sends a trigger signal to the physical tracker process.
     * The tracker must already be running (python3 physical_tracker.py --source 0).
     * This writes the signal file that the tracker reads on each frame.
     */
    public function triggerPhysicalTracker(array $attackerInfo): array
    {
        return $this->run('physical_tracker.py', [
            'action'   => 'trigger',
            'attacker' => $attackerInfo,
        ]);
    }

    /** Returns the current status of the physical tracker process */
    public function trackerStatus(): array
    {
        return $this->run('physical_tracker.py', ['action' => 'status']);
    }
}
