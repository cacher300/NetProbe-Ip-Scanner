import sqlite3


def get_world_db_data():
    try:
        conn = sqlite3.connect('world_scan_results.db')
        cur = conn.cursor()
        cur.execute("""
        SELECT ip_addresses.ip_address, ip_addresses.location, ip_addresses.ip_lookup, GROUP_CONCAT(DISTINCT open_ports.port) as ports
        FROM ip_addresses
        JOIN open_ports ON ip_addresses.id = open_ports.ip_id
        GROUP BY ip_addresses.ip_address
        """)
        data = cur.fetchall()
        return data
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


def setup_database():
    try:
        conn = sqlite3.connect('world_scan_results.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ip_addresses (
                        id INTEGER PRIMARY KEY,
                        ip_address TEXT UNIQUE,
                        location TEXT,
                        ip_lookup TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS open_ports (
                        id INTEGER PRIMARY KEY,
                        ip_id INTEGER,
                        port INTEGER,
                        FOREIGN KEY (ip_id) REFERENCES ip_addresses(id))''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


def insert_scan_result(ip, location, port, ip_lookup):
    try:
        conn = sqlite3.connect('world_scan_results.db')
        c = conn.cursor()

        c.execute("INSERT OR IGNORE INTO ip_addresses (ip_address, location, ip_lookup) VALUES (?, ?, ?)", (ip, location, ip_lookup))
        conn.commit()

        c.execute("SELECT id FROM ip_addresses WHERE ip_address = ?", (ip,))
        ip_id = c.fetchone()[0]

        c.execute("SELECT * FROM open_ports WHERE ip_id = ? AND port = ?", (ip_id, port))
        if not c.fetchone():
            c.execute("INSERT INTO open_ports (ip_id, port) VALUES (?, ?)", (ip_id, port))
            conn.commit()
        else:
            print(f"Port {port} already exists for IP {ip}, skipping insertion.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


