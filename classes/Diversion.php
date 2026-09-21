<?php
namespace Aegis\Classes;
use Aegis\Config\Database;

class Diversion
{
    private Database         $db;
    private AIDeceptionEngine $ai;
    private AttackerProfiler  $profiler;
    private SystemProfiler    $sysProfiler;
    private const THRESHOLD = 60;

    public function __construct()
    {
        $this->db          = Database::getInstance();
        $this->ai          = new AIDeceptionEngine();
        $this->profiler    = new AttackerProfiler();
        $this->sysProfiler = new SystemProfiler();
    }

    public function shouldDivert(int $siteId, string $sessionKey): bool
    {
        $p = $this->db->fetchOne(
            'SELECT max_severity, is_banned FROM aegis_attacker_profile
             WHERE site_id = ? AND session_key = ?',
            [$siteId, $sessionKey]
        );
        return $p && ($p['is_banned'] || $p['max_severity'] >= self::THRESHOLD);
    }

    public function serveDecoy(int $siteId, string $sessionKey,
                               string $method, string $path): never
    {
        $systemType = $this->sysProfiler->detect($siteId);
        $events     = $this->db->fetchAll(
            'SELECT attack_type, severity_score, created_at FROM aegis_attack_log
             WHERE site_id = ? AND session_key = ? ORDER BY created_at ASC',
            [$siteId, $sessionKey]
        );
        $profile   = $this->profiler->summarise($events);
        $lastType  = !empty($events) ? $events[array_key_last($events)]['attack_type'] : 'FAILED_LOGIN';
        $reaction  = $this->ai->generateAttackReaction($lastType, $systemType, $profile);

        if (($ms = $reaction['delay_ms'] ?? rand(80,300)) > 0) usleep($ms * 1000);

        TechDeception::applyHeaders($siteId, $path);

        $http = $reaction['http_status'] ?? 200;
        $body = $this->buildBody($method, $path, $systemType, $siteId, $profile, $reaction);

        http_response_code($http);
        header('Content-Type: application/json');
        echo json_encode($body, JSON_UNESCAPED_UNICODE);
        exit;
    }

    private function buildBody(string $method, string $path, string $systemType,
                               int $siteId, array $profile, array $reaction): mixed
    {
        return match ($reaction['type'] ?? 'NORMAL_DATA') {
            'FAKE_LOGIN_SUCCESS'      => $this->loginSuccess($siteId, $systemType, $profile),
            'FAKE_EXTRACTION_SUCCESS' => $this->extraction($path, $systemType, $profile),
            'FAKE_ADMIN_DATA'         => $this->adminData($systemType, $profile),
            'FAKE_DELETE_SUCCESS'     => $this->deleteSuccess($path),
            'MISLEADING_DB_ERROR'     => $this->dbError($siteId, $path, $profile),
            'NORMAL_REJECT'           => TechDeception::errorResponse($siteId, 401, $path),
            default                   => $this->contextualData($method, $path, $systemType, $profile),
        };
    }

    private function loginSuccess(int $siteId, string $systemType, array $p): array
    {
        $users = $this->ai->generateFakeUsers($systemType, 1, $p['skill_level'] ?? 'SCRIPT_KIDDIE');
        $u     = $users[0] ?? ['id'=>1,'role'=>'Administrator','username'=>'admin','email'=>'admin@system.co.tz'];
        return TechDeception::loginSuccessResponse($siteId, [
            'id'=>$u['id']??1,'username'=>$u['username']??'admin',
            'email'=>$u['email']??'admin@system.co.tz','role'=>$u['role']??'Administrator',
        ]);
    }

    private function extraction(string $path, string $systemType, array $p): array
    {
        $count = ($p['deception_level']??'LOW')==='HIGH' ? rand(40,120) : rand(5,18);
        $users = $this->ai->generateFakeUsers($systemType, min($count,8), $p['skill_level']??'SCRIPT_KIDDIE');
        return ['data'=>$users,'total'=>$count,'extracted'=>$count,
                'query_time'=>round(rand(80,600)/1000,3).'s','server_time'=>date('Y-m-d H:i:s')];
    }

    private function adminData(string $systemType, array $p): array
    {
        $users = $this->ai->generateFakeUsers($systemType, 8, $p['skill_level']??'INTERMEDIATE');
        return ['users'=>$users,'total_users'=>rand(200,5000),'active_sessions'=>rand(5,60),
                'server_time'=>date('Y-m-d H:i:s'),'admin_access'=>true];
    }

    private function deleteSuccess(string $path): array
    {
        preg_match('/(\d+)/', $path, $m);
        $id = (int)($m[1] ?? rand(1,999));
        return ['success'=>true,'deleted'=>true,'id'=>$id,
                'message'=>"Record {$id} permanently deleted.",'timestamp'=>date('c')];
    }

    private function dbError(int $siteId, string $path, array $p): array
    {
        $stack = TechDeception::getStack($siteId);
        return ($p['skill_level']??'') === 'ADVANCED'
            ? $this->ai->generateFakeError($stack['key'], '500')
            : TechDeception::errorResponse($siteId, 500, $path);
    }

    private function contextualData(string $method, string $path,
                                    string $systemType, array $profile): mixed
    {
        $r = $this->ai->generateResponse($path, $systemType, $profile, $method);
        if (!empty($r)) return $r;
        if (in_array($method, ['POST','PUT','PATCH'])) return ['success'=>true,'id'=>rand(100,9999)];
        if ($method === 'DELETE') return ['success'=>true,'deleted'=>true];
        $users = $this->ai->generateFakeUsers($systemType, 5);
        return ['data'=>$users,'total'=>count($users)];
    }
}
