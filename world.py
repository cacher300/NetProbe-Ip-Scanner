import os
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import requests

from world_sql_setup import insert_scan_result, setup_database


def run_world_scan(num_threads, ip_list_file, ports):
    if not 1 <= int(num_threads) <= 128:
        raise ValueError("num_threads must be between 1 and 128")

    def scan_port(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                return ip, port, sock.connect_ex((ip, port)) == 0
        except (OSError, ValueError):
            return ip, port, False

    def scan_ports_on_ip_range(ip_range, port_range, workers):
        open_ports = []
        tasks = ((ip, port) for ip in ip_range for port in port_range)
        max_pending = workers * 4
        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = set()
            for _ in range(max_pending):
                try:
                    pending.add(executor.submit(scan_port, *next(tasks)))
                except StopIteration:
                    break

            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    ip, port, is_open = future.result()
                    if is_open:
                        open_ports.append((ip, port))
                    try:
                        pending.add(executor.submit(scan_port, *next(tasks)))
                    except StopIteration:
                        pass
        return open_ports

    def get_ip_info(ip_address, session, cache):
        if ip_address in cache:
            return cache[ip_address]

        params = {}
        token = os.environ.get("IPINFO_TOKEN")
        if token:
            params["token"] = token
        try:
            response = session.get(
                f"https://ipinfo.io/{ip_address}/json", params=params, timeout=5
            )
            response.raise_for_status()
            ip_info = response.json()
            location = ", ".join(
                [
                    ip_info.get("city", "Unknown City"),
                    ip_info.get("region", "Unknown Region"),
                    ip_info.get("country", "Unknown Country"),
                ]
            )
        except (requests.RequestException, ValueError):
            location = "Unknown location"
        cache[ip_address] = location
        return location

    setup_database()
    with open(ip_list_file, "r", encoding="ascii") as file:
        ip_range = (line.strip() for line in file if line.strip())

    open_ports = scan_ports_on_ip_range(ip_range, list(ports), int(num_threads))
    location_cache = {}
    with requests.Session() as session:
        for ip, port in open_ports:
            location = get_ip_info(ip, session, location_cache)
            ip_lookup = f"https://www.infobyip.com/ip-{ip}.html"
            insert_scan_result(ip, location, port, ip_lookup)
