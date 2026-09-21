<?php
/**
 * Authorization.php
 * ============================================================
 * Solves the IDOR / business-logic gap that Aegis's pattern
 * detection cannot cover: ensuring that the authenticated
 * user actually OWNS or HAS PERMISSION to access the requested
 * resource — regardless of whether the request looks suspicious.
 *
 * Two distinct problems solved here:
 *
 *   1. ROLE-BASED ACCESS CONTROL (RBAC)
 *      "Can this role even perform this action at all?"
 *      e.g. CLIENT cannot call DELETE /api/users/*
 *
 *   2. RESOURCE OWNERSHIP (anti-IDOR)
 *      "Does this user own the specific record they are
 *       requesting, even if their role allows the action?"
 *      e.g. user #5 cannot read invoice #3 (owned by user #2)
 *
 * Usage — drop near the top of any endpoint:
 *
 *   $auth = new Authorization($currentUserId, $currentRole);
 *   $auth->requireRole('ADMIN');                         // role gate
 *   $auth->requireOwnership('invoices', $invoiceId);    // IDOR gate
 *   $auth->requireRoleOrOwnership('MANAGER','orders',$orderId);
 * ============================================================
 */

namespace Aegis\Classes;

use Aegis\Config\Database;

class Authorization
{
    // ----------------------------------------------------------------
    // Role hierarchy — higher index = more privilege.
    // A role at index N can do everything roles < N can do.
    // ----------------------------------------------------------------
    public const ROLES = [
        'GUEST'   => 0,
        'CLIENT'  => 1,
        'SUPPORT' => 2,
        'FINANCE' => 3,
        'MANAGER' => 4,
        'ADMIN'   => 5,
    ];

    // ----------------------------------------------------------------
    // Endpoint permission matrix.
    // Format: 'METHOD /path/pattern' => minimum role required.
    // Patterns support {id} wildcards.
    // ----------------------------------------------------------------
    public const PERMISSIONS = [
        // Public — no auth needed (handled before Authorization runs)
        'POST /api/login'                       => null,
        'POST /api/register'                    => null,

        // Read own profile
        'GET /api/profile'                      => 'CLIENT',
        'PUT /api/profile'                      => 'CLIENT',

        // Invoices — clients can only read their own (ownership check also required)
        'GET /api/invoices'                     => 'CLIENT',
        'GET /api/invoices/{id}'                => 'CLIENT',    // + ownership
        'POST /api/invoices'                    => 'FINANCE',
        'PUT /api/invoices/{id}'                => 'FINANCE',
        'DELETE /api/invoices/{id}'             => 'MANAGER',

        // Orders
        'GET /api/orders'                       => 'CLIENT',
        'GET /api/orders/{id}'                  => 'CLIENT',    // + ownership
        'POST /api/orders'                      => 'CLIENT',
        'PUT /api/orders/{id}'                  => 'SUPPORT',
        'DELETE /api/orders/{id}'               => 'MANAGER',

        // Users — clients cannot list all users (IDOR vector)
        'GET /api/users'                        => 'MANAGER',
        'GET /api/users/{id}'                   => 'SUPPORT',
        'POST /api/users'                       => 'ADMIN',
        'PUT /api/users/{id}'                   => 'ADMIN',
        'DELETE /api/users/{id}'                => 'ADMIN',

        // Admin / dashboard
        'GET /admin'                            => 'ADMIN',
        'GET /admin/{any}'                      => 'ADMIN',
        'GET /api/admin/{any}'                  => 'ADMIN',

        // Reports
        'GET /api/reports'                      => 'MANAGER',
        'POST /api/reports'                     => 'MANAGER',
        'GET /api/reports/{id}'                 => 'FINANCE',

        // Aegis dashboard routes
        'GET /aegis/admin/{any}'                => 'ADMIN',
        'POST /aegis/admin/{any}'               => 'ADMIN',
    ];

    // Tables where we enforce ownership — maps table name to the
    // column that stores the owning user's ID.
    private const OWNER_COLUMNS = [
        'invoices'   => 'user_id',
        'orders'     => 'user_id',
        'documents'  => 'owner_id',
        'tickets'    => 'created_by',
        'sites'      => 'owner_id',
        'reports'    => 'created_by',
    ];

    // ----------------------------------------------------------------

    private int    $userId;
    private string $role;
    private Database $db;

    /**
     * @param int    $userId  Current authenticated user's ID
     * @param string $role    Their role string (e.g. 'ADMIN', 'CLIENT')
     */
    public function __construct(int $userId, string $role)
    {
        $this->userId = $userId;
        $this->role   = strtoupper(trim($role));
        $this->db     = Database::getInstance();
    }

    // ================================================================
    //  ROLE CHECKS
    // ================================================================

    /**
     * Aborts with HTTP 403 if the current user's role is below $minimum.
     *
     * Usage: $auth->requireRole('MANAGER');
     */
    public function requireRole(string $minimum): void
    {
        if (!$this->hasRole($minimum)) {
            $this->deny("Role '{$this->role}' cannot perform this action. Requires '{$minimum}' or above.");
        }
    }

    /**
     * Returns true if the current role meets or exceeds $minimum.
     */
    public function hasRole(string $minimum): bool
    {
        $current = self::ROLES[$this->role]       ?? -1;
        $needed  = self::ROLES[strtoupper($minimum)] ?? PHP_INT_MAX;
        return $current >= $needed;
    }

    /**
     * Checks the permission matrix for the current HTTP method + path.
     * Call once at the start of a request to gate the whole endpoint.
     *
     * Usage: $auth->requirePermission('DELETE', '/api/users/42');
     */
    public function requirePermission(string $method, string $path): void
    {
        $required = $this->resolvePermission(strtoupper($method), $path);

        if ($required === false) {
            // Endpoint not in the matrix — deny by default (fail-safe)
            $this->deny("Endpoint not registered in permission matrix: {$method} {$path}");
        }

        if ($required === null) {
            // Explicitly public
            return;
        }

        $this->requireRole($required);
    }

    // ================================================================
    //  OWNERSHIP CHECKS (anti-IDOR)
    // ================================================================

    /**
     * Verifies that the record in $table with $recordId is owned by
     * the current user. Aborts 403 if not.
     *
     * IMPORTANT: this performs a real DB lookup every time — that
     * is intentional. Never trust client-supplied ownership hints.
     *
     * Usage: $auth->requireOwnership('invoices', $id);
     */
    public function requireOwnership(string $table, int $recordId): void
    {
        if (!$this->ownsRecord($table, $recordId)) {
            $this->deny("User #{$this->userId} does not own {$table}#{$recordId}.");
        }
    }

    /**
     * Allows access if the user has $role OR owns the specific record.
     * Useful for "managers can see all invoices, clients only their own."
     *
     * Usage: $auth->requireRoleOrOwnership('MANAGER', 'invoices', $id);
     */
    public function requireRoleOrOwnership(string $role, string $table, int $recordId): void
    {
        if ($this->hasRole($role)) return;          // role covers it
        if ($this->ownsRecord($table, $recordId)) return; // ownership covers it
        $this->deny(
            "Access to {$table}#{$recordId} requires role '{$role}' "
            . "or ownership. User #{$this->userId} has neither."
        );
    }

    /**
     * Returns true if the current user owns $recordId in $table.
     * Returns true unconditionally for ADMIN (admins see everything).
     */
    public function ownsRecord(string $table, int $recordId): bool
    {
        if ($this->hasRole('ADMIN')) return true;

        $col = self::OWNER_COLUMNS[$table] ?? null;
        if ($col === null) {
            // Table not in the ownership map — fail safe (deny)
            return false;
        }

        // Parameterised query — never string-concatenate $table here.
        // Table name cannot be a parameter, so we allowlist it first.
        $allowedTables = array_keys(self::OWNER_COLUMNS);
        if (!in_array($table, $allowedTables, true)) {
            return false;
        }

        $row = $this->db->fetchOne(
            "SELECT {$col} FROM `{$table}` WHERE id = ? LIMIT 1",
            [$recordId]
        );

        if (!$row) return false; // record doesn't exist — deny
        return (int) $row[$col] === $this->userId;
    }

    /**
     * Convenience: apply full permission + ownership check in one call.
     * Use this on every resource endpoint.
     *
     * Usage:
     *   $auth->guard('GET', '/api/invoices/42', 'invoices', 42);
     *
     * - Checks the permission matrix for the role.
     * - If the role alone would allow it (e.g. MANAGER), passes.
     * - If the role requires ownership (e.g. CLIENT reading their own
     *   invoice), additionally checks the ownership column.
     */
    public function guard(string $method, string $path, ?string $table = null, ?int $recordId = null): void
    {
        $this->requirePermission($method, $path);

        if ($table !== null && $recordId !== null && !$this->hasRole('MANAGER')) {
            // Non-managers must also own the specific record
            $this->requireOwnership($table, $recordId);
        }
    }

    // ================================================================
    //  STATIC FACTORY — builds from a JWT payload or session
    // ================================================================

    /**
     * Build from a decoded JWT payload array.
     *
     * Usage:
     *   $payload = JWTHelper::decode($token);
     *   $auth    = Authorization::fromJwtPayload($payload);
     */
    public static function fromJwtPayload(array $payload): self
    {
        return new self(
            (int) ($payload['sub'] ?? $payload['user_id'] ?? 0),
            (string) ($payload['role'] ?? 'GUEST')
        );
    }

    /**
     * Build from a PHP session (SIMAP-style).
     *
     * Usage:
     *   session_start();
     *   $auth = Authorization::fromSession();
     */
    public static function fromSession(): self
    {
        return new self(
            (int) ($_SESSION['user_id'] ?? 0),
            (string) ($_SESSION['role']    ?? 'GUEST')
        );
    }

    // ================================================================
    //  PRIVATE
    // ================================================================

    /**
     * Resolves the permission matrix for method + path.
     * Returns: string (role required) | null (public) | false (not found)
     */
    private function resolvePermission(string $method, string $path): string|null|false
    {
        foreach (self::PERMISSIONS as $key => $role) {
            [$mMethod, $mPath] = explode(' ', $key, 2);
            if ($mMethod !== $method) continue;
            if ($this->pathMatches($mPath, $path)) return $role;
        }
        return false; // not in matrix → deny
    }

    /**
     * Matches a path pattern (with {id} and {any} wildcards) against
     * a real request path.
     */
    private function pathMatches(string $pattern, string $path): bool
    {
        $regex = preg_replace(
            ['/\{id\}/', '/\{any\}/', '/\//'],
            ['\d+',     '.+',       '\/'],
            $pattern
        );
        return (bool) preg_match('#^' . $regex . '$#', $path);
    }

    /**
     * Sends a JSON 403 response and exits.
     * Logs the denial to error_log for audit purposes.
     */
    private function deny(string $reason): never
    {
        error_log("[Aegis Authorization] DENIED user#{$this->userId} ({$this->role}): {$reason}");

        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'error'  => 'Access denied',
            'reason' => $reason,
        ]);
        exit;
    }
}
