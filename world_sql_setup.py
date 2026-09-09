import sqlite3
from pathlib import Path


DATABASE = Path(__file__).resolve().parent / "world_scan_results.db"


def _connect():
    conn = sqlite3.connect(DATABASE, timeout=30)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_world_db_data():
    conn = _connect()
    try:
        return conn.execute(
            """
            SELECT ip_addresses.ip_address, ip_addresses.location,
                   ip_addresses.ip_lookup,
                   GROUP_CONCAT(DISTINCT open_ports.port) AS ports
            FROM ip_addresses
            LEFT JOIN open_ports ON ip_addresses.id = open_ports.ip_id
            GROUP BY ip_addresses.id
            """
        ).fetchall()
    finally:
        conn.close()


def setup_database():
    conn = _connect()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_addresses (
                    id INTEGER PRIMARY KEY,
                    ip_address TEXT UNIQUE,
                    location TEXT,
                    ip_lookup TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS open_ports (
                    id INTEGER PRIMARY KEY,
                    ip_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    FOREIGN KEY (ip_id) REFERENCES ip_addresses(id)
                )
                """
            )
            conn.execute(
                """
                DELETE FROM open_ports
                WHERE id NOT IN (
                    SELECT MIN(id) FROM open_ports GROUP BY ip_id, port
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_world_open_ports_ip_port "
                "ON open_ports(ip_id, port)"
            )
    finally:
        conn.close()


def insert_scan_result(ip, location, port, ip_lookup):
    conn = _connect()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO ip_addresses (ip_address, location, ip_lookup)
                VALUES (?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    location = excluded.location,
                    ip_lookup = excluded.ip_lookup
                """,
                (ip, location, ip_lookup),
            )
            ip_id = conn.execute(
                "SELECT id FROM ip_addresses WHERE ip_address = ?", (ip,)
            ).fetchone()[0]
            conn.execute(
                "INSERT OR IGNORE INTO open_ports (ip_id, port) VALUES (?, ?)",
                (ip_id, port),
            )
    finally:
        conn.close()
