<?php
namespace Aegis\Classes;

class AIDeceptionEngine
{
    private string $pythonBin;
    private string $modelScript;
    private int    $cacheTtl = 480; // 8 min

    public function __construct()
    {
        $this->pythonBin   = getenv('AEGIS_PYTHON_BIN') ?: 'python3';
        $this->modelScript = dirname(__DIR__) . '/python/ai_model.py';
    }

    // ── Public API ──────────────────────────────────────────────

    public function generateFakeUsers(string $systemType, int $count = 6,
                                      string $skillLevel = 'SCRIPT_KIDDIE'): array
    {
        $ck     = "users_{$systemType}_{$count}_{$skillLevel}";
        $cached = $this->cache($ck);
        if ($cached !== null) return $cached;
        $result = $this->call(['action'=>'generate_users','system_type'=>$systemType,
                               'count'=>$count,'skill_level'=>$skillLevel]);
        $users  = $result['users'] ?? $this->fallbackUsers($systemType, $count);
        $this->cache($ck, $users);
        return $users;
    }

    public function generateResponse(string $endpoint, string $systemType,
                                     array $attackerProfile, string $method = 'GET'): array
    {
        $result = $this->call([
            'action'      => 'generate_response',
            'endpoint'    => $endpoint,
            'system_type' => $systemType,
            'phase'       => $attackerProfile['phase']       ?? 'RECONNAISSANCE',
            'skill_level' => $attackerProfile['skill_level'] ?? 'SCRIPT_KIDDIE',
            'method'      => $method,
        ]);
        return (isset($result['error']) || empty($result))
            ? $this->fallbackResponse($endpoint, $systemType, $method)
            : $result;
    }

    public function generateAttackReaction(string $attackType, string $systemType,
                                           array $attackerProfile): array
    {
        $phase  = $attackerProfile['phase']       ?? 'RECONNAISSANCE';
        $skill  = $attackerProfile['skill_level'] ?? 'SCRIPT_KIDDIE';
        $events = $attackerProfile['total_events'] ?? 0;
        return match ($phase) {
            'RECONNAISSANCE'    => ['type'=>'NORMAL_DATA',            'delay_ms'=>rand(80,220),  'http_status'=>200],
            'CREDENTIAL_ATTACK' => $events >= rand(8,15)
                                   ? ['type'=>'FAKE_LOGIN_SUCCESS',   'delay_ms'=>rand(600,1400),'http_status'=>200]
                                   : ['type'=>'NORMAL_REJECT',        'delay_ms'=>rand(350,800), 'http_status'=>401],
            'INJECTION'         => $skill === 'ADVANCED'
                                   ? ['type'=>'FAKE_EXTRACTION_SUCCESS','delay_ms'=>rand(1800,5000),'http_status'=>200]
                                   : ['type'=>'MISLEADING_DB_ERROR',  'delay_ms'=>rand(100,350), 'http_status'=>500],
            'ESCALATION'        => ['type'=>'FAKE_ADMIN_DATA',        'delay_ms'=>rand(200,600), 'http_status'=>200],
            'DESTRUCTION'       => ['type'=>'FAKE_DELETE_SUCCESS',    'delay_ms'=>rand(300,800), 'http_status'=>200],
            default             => ['type'=>'NORMAL_DATA',            'delay_ms'=>rand(80,250),  'http_status'=>200],
        };
    }

    public function selectFakeTech(string $realTech, int $siteId): array
    {
        $ck = "tech_{$siteId}";
        $c  = $this->cache($ck);
        if ($c !== null) return $c;
        $r = $this->call(['action'=>'fake_tech','real'=>$realTech,'site_id'=>$siteId]);
        $t = !empty($r['key']) ? $r : ['key'=>'DJANGO','server'=>'nginx/1.24.0',
             'powered_by'=>null,'framework'=>'Django/4.2.7','language'=>'Python 3.11'];
        $this->cache($ck, $t);
        return $t;
    }

    public function generateFakeError(string $fakeTechKey, string $errorType = '500'): array
    {
        $r = $this->call(['action'=>'fake_error','fake_tech'=>$fakeTechKey,'error_type'=>$errorType]);
        return (isset($r['error']) || empty($r))
            ? ['error'=>'Internal server error','status'=>500]
            : $r;
    }

    // ── Python subprocess call ──────────────────────────────────

    private function call(array $params): array
    {
        if (!file_exists($this->modelScript)) return ['error'=>'ai_model.py not found'];
        $cmd    = sprintf('%s %s --args %s 2>/dev/null',
                    escapeshellcmd($this->pythonBin),
                    escapeshellarg($this->modelScript),
                    escapeshellarg(json_encode($params)));
        $output = shell_exec($cmd);
        if (!$output) return ['error'=>'No output'];
        $decoded = json_decode(trim($output), true);
        return is_array($decoded) ? $decoded : ['error'=>'Bad JSON'];
    }

    // ── Fallbacks ───────────────────────────────────────────────

    private function fallbackUsers(string $systemType, int $count): array
    {
        $names = ['Amina Hassan','Baraka Juma','Fatuma Ali','Hassan Omar',
                  'Neema Saidi','Juma Mwangi','Salma Rashid','Bakari Khatib'];
        $roles = ['EDUCATION'=>['Student','Lecturer','Registrar'],
                  'WIFI_MANAGEMENT'=>['Subscriber','Network Admin','Reseller'],
                  'ECOMMERCE'=>['Customer','Vendor','Admin'],
                  'AGENCY'=>['Client','Account Manager','Content Creator'],
                  'HEALTHCARE'=>['Patient','Doctor','Nurse'],
                  'GENERIC_BUSINESS'=>['User','Manager','Admin']];
        $r     = $roles[$systemType] ?? $roles['GENERIC_BUSINESS'];
        $doms  = ['growthhub.co.tz','cbetanzania.ac.tz','isp.co.tz','gmail.com'];
        $out   = [];
        for ($i = 0; $i < $count; $i++) {
            $name    = $names[$i % count($names)];
            $slug    = strtolower(str_replace(' ', '.', $name));
            $out[]   = ['id'=>$i+1,'username'=>$slug,'full_name'=>$name,
                        'email'=>$slug.'@'.$doms[$i%count($doms)],
                        'role'=>$r[$i%count($r)],'is_active'=>true,
                        'created_at'=>date('Y-m-d H:i:s',strtotime('-'.rand(10,730).' days'))];
        }
        return $out;
    }

    private function fallbackResponse(string $endpoint, string $systemType, string $method): array
    {
        if (in_array($method, ['POST','PUT','PATCH'])) return ['success'=>true,'id'=>rand(100,9999)];
        if ($method === 'DELETE')                      return ['success'=>true,'deleted'=>true];
        return ['data'=>$this->fallbackUsers($systemType,5),'total'=>5];
    }

    // ── File cache ──────────────────────────────────────────────

    private function cache(string $key, ?array $data = null): ?array
    {
        $path = sys_get_temp_dir() . '/aegis_' . md5($key) . '.json';
        if ($data === null) {
            if (!file_exists($path) || filemtime($path) < time() - $this->cacheTtl) return null;
            $v = json_decode(file_get_contents($path), true);
            return is_array($v) ? $v : null;
        }
        file_put_contents($path, json_encode($data));
        return null;
    }
}
