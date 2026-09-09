import csv
import hmac
import io
import ipaddress
import logging
import os
import secrets
import sqlite3
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

import local
import world
from local_sql_setup import get_local_db_data
from world_sql_setup import get_world_db_data


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "ip_ranges.db"
LOCAL_DATABASE = BASE_DIR / "local_scan_results.db"
WORLD_DATABASE = BASE_DIR / "world_scan_results.db"
MAX_SCAN_HOSTS = 65_536
MAX_PORTS = 1_024
MAX_THREADS = 128

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.secret_key = os.environ.get("NETPROBE_SECRET_KEY") or secrets.token_hex(32)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scan_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="netprobe-scan")
scan_lock = threading.Lock()
scan_running = False


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=30)
    return db


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": csrf_token}


def _validate_csrf():
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Invalid CSRF token")


def _require_admin():
    _validate_csrf()
    configured_token = os.environ.get("NETPROBE_ADMIN_TOKEN")
    supplied_token = request.form.get("admin_token") or request.headers.get("X-Admin-Token")
    if not configured_token:
        abort(503, description="Set NETPROBE_ADMIN_TOKEN before using destructive actions")
    if not supplied_token or not hmac.compare_digest(configured_token, supplied_token):
        abort(403, description="Invalid admin token")


def _parse_ports(raw_ports):
    if not raw_ports or not raw_ports.strip():
        raise ValueError("Enter at least one port")

    parsed = set()
    for raw_part in raw_ports.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("Port list contains an empty item")
        if "-" in part:
            pieces = part.split("-")
            if len(pieces) != 2:
                raise ValueError(f"Invalid port range: {part}")
            try:
                start, end = (int(value.strip()) for value in pieces)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {part}") from exc
            if start > end:
                raise ValueError(f"Port range is reversed: {part}")
            if start < 1 or end > 65_535:
                raise ValueError("Ports must be between 1 and 65535")
            if end - start + 1 > MAX_PORTS:
                raise ValueError(f"Select no more than {MAX_PORTS} ports")
            parsed.update(range(start, end + 1))
        else:
            try:
                parsed.add(int(part))
            except ValueError as exc:
                raise ValueError(f"Invalid port: {part}") from exc

    if any(port < 1 or port > 65_535 for port in parsed):
        raise ValueError("Ports must be between 1 and 65535")
    if len(parsed) > MAX_PORTS:
        raise ValueError(f"Select no more than {MAX_PORTS} ports")
    return sorted(parsed)


def _parse_threads(raw_threads):
    try:
        threads = int(raw_threads)
    except (TypeError, ValueError) as exc:
        raise ValueError("Threads must be a whole number") from exc
    if not 1 <= threads <= MAX_THREADS:
        raise ValueError(f"Threads must be between 1 and {MAX_THREADS}")
    return threads


def _parse_ip_range(raw_target):
    if not raw_target or not raw_target.strip():
        raise ValueError("Enter an IP range")

    target = raw_target.strip()
    if "-" in target:
        parts = target.split("-")
        if len(parts) != 2:
            raise ValueError("Use START-IP-END-IP for an explicit range")
        try:
            start = ipaddress.ip_address(parts[0].strip())
            end = ipaddress.ip_address(parts[1].strip())
        except ValueError as exc:
            raise ValueError("Enter valid IPv4 addresses") from exc
        if start.version != 4 or end.version != 4:
            raise ValueError("Only IPv4 ranges are supported")
        if int(start) > int(end):
            raise ValueError("IP range is reversed")
        count = int(end) - int(start) + 1
        if count > MAX_SCAN_HOSTS:
            raise ValueError(f"Scan no more than {MAX_SCAN_HOSTS} hosts at a time")
        return [str(ipaddress.IPv4Address(value)) for value in range(int(start), int(end) + 1)]

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address or CIDR range") from exc
    if network.version != 4:
        raise ValueError("Only IPv4 ranges are supported")
    if network.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(f"Scan no more than {MAX_SCAN_HOSTS} hosts at a time")
    return [str(ip) for ip in network.hosts()]


def _begin_scan():
    global scan_running
    with scan_lock:
        if scan_running:
            return False
        scan_running = True
        return True


def _finish_scan():
    global scan_running
    with scan_lock:
        scan_running = False


def _run_local_scan(threads, ports):
    try:
        local.run_local_scan(threads, ports)
    except Exception:
        logger.exception("Local scan failed")
    finally:
        _finish_scan()


def _run_world_scan(threads, ip_range, ports):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", delete=False, dir=BASE_DIR
        ) as temp_file:
            temp_file.write("\n".join(ip_range))
            temp_path = Path(temp_file.name)
        world.run_world_scan(threads, str(temp_path), ports)
    except Exception:
        logger.exception("World scan failed")
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        _finish_scan()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        _validate_csrf()
        try:
            scan_type = request.form.get("scan_type")
            threads = _parse_threads(request.form.get("threads"))
            ports = _parse_ports(request.form.get("ports"))
            if scan_type == "local_network":
                if not _begin_scan():
                    flash("A scan is already running", "error")
                else:
                    scan_executor.submit(_run_local_scan, threads, ports)
                    flash("Local scan started. Refresh the results page when it finishes.", "success")
                return redirect(url_for("local_table"))
            if scan_type == "ip_range":
                ip_range = _parse_ip_range(request.form.get("ip_range"))
                if not _begin_scan():
                    flash("A scan is already running", "error")
                else:
                    scan_executor.submit(_run_world_scan, threads, ip_range, ports)
                    flash("World scan started. Refresh the results page when it finishes.", "success")
                return redirect(url_for("world_table"))
            raise ValueError("Select a valid scan type")
        except (TypeError, ValueError) as exc:
            flash(str(exc), "error")
            return render_template("index.html"), 400

    return render_template("index.html")


def _quote_identifier(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def _allowed_ip_range_tables():
    rows = get_db().execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {row[0] for row in rows}


@app.route("/get_ip_blocks")
def get_ip_blocks():
    result = {}
    db = get_db()
    for table_name in sorted(_allowed_ip_range_tables()):
        rows = db.execute(
            f"SELECT start_ip, end_ip FROM {_quote_identifier(table_name)}"
        ).fetchall()
        result[table_name] = [
            {"start of block": row[0], "end of block": row[1]} for row in rows
        ]
    return jsonify(result)


@app.route("/world_table")
def world_table():
    return render_template("world_table.html", data=get_world_db_data())


@app.route("/local_table")
def local_table():
    return render_template("local_table.html", data=get_local_db_data())


def _csv_download(database, query, headers):
    conn = sqlite3.connect(database, timeout=30)
    try:
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        as_attachment=True,
        download_name="ip_ports_export.csv",
        mimetype="text/csv",
    )


@app.route("/world_download")
def world_download():
    return _csv_download(
        WORLD_DATABASE,
        """
        SELECT ip_addresses.id, ip_addresses.ip_address,
               group_concat(open_ports.port, ', ') AS ports,
               ip_addresses.location, ip_addresses.ip_lookup
        FROM ip_addresses
        LEFT JOIN open_ports ON ip_addresses.id = open_ports.ip_id
        GROUP BY ip_addresses.id
        """,
        ["ID", "IP Address", "Ports Open", "Location", "IP Lookup"],
    )


@app.route("/local_download")
def local_download():
    return _csv_download(
        LOCAL_DATABASE,
        """
        SELECT ip_addresses.id, ip_addresses.ip_address,
               GROUP_CONCAT(open_ports.port, ', ') AS ports,
               ip_addresses.name, ip_addresses.type, ip_addresses.os,
               ip_addresses.mac_address, ip_addresses.status
        FROM ip_addresses
        LEFT JOIN open_ports ON ip_addresses.id = open_ports.ip_id
        GROUP BY ip_addresses.id
        """,
        ["ID", "IP Address", "Ports Open", "Name", "Type", "OS", "Mac Address", "Status"],
    )


def _wipe_database(database):
    conn = sqlite3.connect(database, timeout=30)
    try:
        with conn:
            conn.execute("DELETE FROM open_ports")
            conn.execute("DELETE FROM ip_addresses")
    finally:
        conn.close()


@app.post("/local_wipe")
def local_wipe_database():
    _require_admin()
    _wipe_database(LOCAL_DATABASE)
    return redirect(url_for("local_table"))


@app.post("/world_wipe")
def world_wipe_database():
    _require_admin()
    _wipe_database(WORLD_DATABASE)
    return redirect(url_for("world_table"))


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


@app.route("/directory")
def directory():
    return render_template("directory.html", tables=sorted(_allowed_ip_range_tables()))


@app.route("/table/<name>")
def table(name):
    if name not in _allowed_ip_range_tables():
        abort(404)
    db = get_db()
    data = db.execute(f"SELECT * FROM {_quote_identifier(name)}").fetchall()
    return render_template("table.html", name=name, data=data)


if __name__ == "__main__":
    app.run(debug=False)
