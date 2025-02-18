<?php
require_once __DIR__ . '/../vendor/autoload.php';

// Cargar el archivo .env
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../'); // Si .env está en el directorio padre
$dotenv->load();

/**
 * Conexión a PostgreSQL
 * @return PDO
 */
function connectPostgres()
{
    try {
        $connectPostgres = new PDO(
            "pgsql:host=" . $_ENV['DB_HOST'] . ";dbname=" . $_ENV['DB_NAME'] . ";port=" . $_ENV['DB_PORT'],
            $_ENV['DB_USER'],
            $_ENV['DB_PASSWORD']
        );
        $connectPostgres->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // echo json_encode(['success' => 'Conexión a PostgresSQL exitosa'], JSON_UNESCAPED_UNICODE);
        return $connectPostgres;
    } catch (PDOException $e) {
        die(json_encode(['error' => 'Conexión a PostgreSQL fallida: ' . $e->getMessage()]));
    }
}

/**
 * Conexión a MariaDB
 * @return PDO
 */
function connectMariaDB()
{
    try {
        $connectMariaDB = new PDO(
            "mysql:host=" . $_ENV['DB_MARIADB_HOST'] . ";dbname=" . $_ENV['DB_MARIADB_NAME'] . ";charset=utf8;port=" . $_ENV['DB_MARIADB_PORT'],
            $_ENV['DB_MARIADB_USER'],
            $_ENV['DB_MARIADB_PASSWORD']
        );
        $connectMariaDB->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // echo json_encode(['success' => 'Conexión a MariaDB exitosa'], JSON_UNESCAPED_UNICODE);
        return $connectMariaDB;
    } catch (PDOException $e) {
        die(json_encode(['error' => 'Conexión a MariaDB fallida: ' . $e->getMessage()]));
    }
}
