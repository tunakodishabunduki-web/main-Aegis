<?php
/**
 * Database.php
 * PDO singleton connection class — matches SIMAP's database layer.
 * Reads credentials from environment variables or a local config file.
 */

namespace Aegis\Config;

use PDO;
use PDOException;

class Database
{
    private static ?Database $instance = null;
    private PDO $pdo;

    private function __construct()
    {
        $host     = getenv('DB_HOST')   ?: '127.0.0.1';
        $dbname   = getenv('DB_NAME')   ?: 'aegis_db';
        $user     = getenv('DB_USER')   ?: 'root';
        $password = getenv('DB_PASS')   ?: '';
        $charset  = 'utf8mb4';

        $dsn = "mysql:host={$host};dbname={$dbname};charset={$charset}";

        try {
            $this->pdo = new PDO($dsn, $user, $password, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            // Never expose credentials in output
            error_log('[Aegis] DB connection failed: ' . $e->getMessage());
            throw new \RuntimeException('Database connection failed.');
        }
    }

    public static function getInstance(): Database
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getPdo(): PDO
    {
        return $this->pdo;
    }

    /** Convenience wrapper: prepare + execute, returns PDOStatement */
    public function query(string $sql, array $params = []): \PDOStatement
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /** Returns all rows as an array of associative arrays */
    public function fetchAll(string $sql, array $params = []): array
    {
        return $this->query($sql, $params)->fetchAll();
    }

    /** Returns the first matching row or null */
    public function fetchOne(string $sql, array $params = []): ?array
    {
        $row = $this->query($sql, $params)->fetch();
        return $row ?: null;
    }

    /** Returns a single scalar value */
    public function fetchScalar(string $sql, array $params = []): mixed
    {
        return $this->query($sql, $params)->fetchColumn();
    }

    /** Inserts a row and returns the last insert ID */
    public function insert(string $sql, array $params = []): string
    {
        $this->query($sql, $params);
        return $this->pdo->lastInsertId();
    }

    // Prevent cloning / unserialization of singleton
    private function __clone() {}
    public function __wakeup(): never
    {
        throw new \RuntimeException('Singleton cannot be unserialized.');
    }
}
