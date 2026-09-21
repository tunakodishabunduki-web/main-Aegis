<?php
namespace Aegis\Classes;
use Aegis\Config\Database;

class SystemProfiler
{
    private const SIGNATURES = [
        'EDUCATION'      => ['student','college','university','school','academic','cbe','course','grade','exam','faculty','lms','enrollment','udsm','campus'],
        'WIFI_MANAGEMENT'=> ['wifi','hotspot','radius','voucher','bandwidth','router','mikrotik','captive','isp','pppoe','dhcp','ubiquiti','subscriber'],
        'ECOMMERCE'      => ['shop','store','product','cart','order','merchant','inventory','duka','market','vendor','mpesa','selcom','checkout'],
        'RESTAURANT'     => ['restaurant','menu','food','chef','table','reservation','kitchen','dish','chakula','mkahawa','waiter'],
        'HEALTHCARE'     => ['hospital','clinic','patient','doctor','nurse','appointment','prescription','medical','ward','pharmacy'],
        'AGENCY'         => ['agency','social','media','campaign','analytics','instagram','facebook','tiktok','growthhub','brand','marketing'],
        'SAAS'           => ['saas','platform','subscription','plan','billing','workspace','webhook','metric','usage','api key'],
        'PROPERTY'       => ['property','real estate','tenant','landlord','rent','lease','apartment','plot'],
    ];
    private const DEFAULT = 'GENERIC_BUSINESS';
    private const LABELS  = [
        'EDUCATION'      => 'Student / Academic Portal',
        'WIFI_MANAGEMENT'=> 'WiFi / Network Management',
        'ECOMMERCE'      => 'E-Commerce / Marketplace',
        'RESTAURANT'     => 'Restaurant / Food Service',
        'HEALTHCARE'     => 'Healthcare / Medical System',
        'AGENCY'         => 'Social Media / Digital Agency',
        'SAAS'           => 'SaaS Platform',
        'PROPERTY'       => 'Property Management',
        'GENERIC_BUSINESS'=> 'Generic Business System',
    ];
    private Database $db;
    private static array $cache = [];

    public function __construct() { $this->db = Database::getInstance(); }

    public function detect(int $siteId): string
    {
        if (isset(self::$cache[$siteId])) return self::$cache[$siteId];
        $site = $this->db->fetchOne('SELECT site_name, site_url, system_type FROM aegis_sites WHERE id = ?', [$siteId]);
        if (!$site) return self::DEFAULT;
        if (!empty($site['system_type'])) { self::$cache[$siteId] = strtoupper($site['system_type']); return self::$cache[$siteId]; }
        $hay = strtolower(($site['site_name'] ?? '') . ' ' . ($site['site_url'] ?? ''));
        foreach (self::SIGNATURES as $type => $kws) {
            foreach ($kws as $kw) { if (str_contains($hay, $kw)) { self::$cache[$siteId] = $type; return $type; } }
        }
        $roles = $this->db->fetchAll('SELECT fake_role FROM aegis_decoy_users WHERE site_id = ? LIMIT 10', [$siteId]);
        $rt    = strtolower(implode(' ', array_column($roles, 'fake_role')));
        foreach (self::SIGNATURES as $type => $kws) {
            foreach ($kws as $kw) { if (str_contains($rt, $kw)) { self::$cache[$siteId] = $type; return $type; } }
        }
        self::$cache[$siteId] = self::DEFAULT;
        return self::DEFAULT;
    }

    public static function label(string $type): string { return self::LABELS[$type] ?? 'Generic Business System'; }
    public static function allTypes(): array
    {
        $r = [];
        foreach (self::LABELS as $k => $v) $r[$k] = $v;
        return $r;
    }
}
