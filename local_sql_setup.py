import sqlite3

def get_local_db_data():
    conn = None
    try:
        conn = sqlite3.connect('local_scan_results.db')
        cur = conn.cursor()
        cur.execute("""
        SELECT ip_addresses.ip_address, ip_addresses.name, ip_addresses.type, ip_addresses.os, ip_addresses.mac_address, ip_addresses.status, GROUP_CONCAT(DISTINCT open_ports.port) as ports
        FROM ip_addresses
        JOIN open_ports ON ip_addresses.id = open_ports.ip_id
        GROUP BY ip_addresses.ip_address
        """)
        data = cur.fetchall()
        return data
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def setup_database():
    conn = None
    try:
        conn = sqlite3.connect('local_scan_results.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE,
                name TEXT,
                type TEXT,
                os TEXT,
                mac_address TEXT,
                status TEXT
            )''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY,
                ip_id INTEGER,
                port INTEGER,
                FOREIGN KEY (ip_id) REFERENCES ip_addresses(id)
            )''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def insert_scan_result(ip, port, name=None, type=None, os=None, mac_address=None, status=None):
    conn = None
    try:
        conn = sqlite3.connect('local_scan_results.db')
        c = conn.cursor()

        # Insert or ignore new IP address entry
        c.execute("INSERT OR IGNORE INTO ip_addresses (ip_address, name, type, os, mac_address, status) VALUES (?, ?, ?, ?, ?, ?)",
                  (ip, name, type, os, mac_address, status))
        conn.commit()

        # Retrieve ID for the IP address
        c.execute("SELECT id FROM ip_addresses WHERE ip_address = ?", (ip,))
        ip_id = c.fetchone()
        if ip_id:
            ip_id = ip_id[0]
            c.execute("SELECT * FROM open_ports WHERE ip_id = ? AND port = ?", (ip_id, port))
            if not c.fetchone():
                c.execute("INSERT INTO open_ports (ip_id, port) VALUES (?, ?)", (ip_id, port))
                conn.commit()
            else:
                print(f"Port {port} already exists for IP {ip}, skipping insertion.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
