import ipaddress
import threading
from queue import Queue, Empty
from local_sql_setup import setup_database, insert_scan_result
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sr1, conf
from scapy.layers.inet import IP, ICMP
from mac_vendor_lookup import MacLookup
import nmap
import socket
import time


def run_local_scan(num_threads,ports):
    stop_event = threading.Event()
    q = Queue()
    results_queue = Queue()
    threads = []

    def get_local_ip():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]

    def get_ip_range():
        local_ip = get_local_ip()
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return [str(ip) for ip in network.hosts()]

    def scan_port(ip, port, timeout=3):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, int(port)))
                return True, (ip, port)
        except (socket.timeout, socket.error):
            return False, None

    def is_ip_alive(ip):
        conf.verb = 0
        response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        return response is not None

    def check_ip(ip):
        if is_ip_alive(ip):
            print(ip)
            mac_address = get_mac(ip)
            name = get_hostname(ip)
            device_type = get_device_info(mac_address) if mac_address != 'NA' else 'NA'
            os = detect_device_type(ip)
            insert_scan_result(ip, 'NA', name, device_type, os, mac_address, 'Alive')

    def threaded_ip_check(ip_list):
        threads = [threading.Thread(target=check_ip, args=(ip,)) for ip in ip_list]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def threader():
        while not stop_event.is_set():
            try:
                worker = q.get(timeout=1)
            except Empty:
                continue
            try:
                for port in port_list:
                    if stop_event.is_set():
                        print(f"Stopping as flagged. Current IP: {worker}")
                        break
                    success, result = scan_port(worker, port)
                    if success:
                        results_queue.put(result)
            finally:
                q.task_done()
                print(f"Task done for {worker}")

    def start_local_scan(threads_num):
        setup_database()
        has_open = []

        for _ in range(threads_num):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()
            threads.append(t)

        ip_list = get_ip_range()
        for ip in ip_list:
            q.put(ip)

        q.join()
        stop_event.set()

        while not results_queue.empty():
            ip, port = results_queue.get()
            mac_address = get_mac(ip)
            name = get_hostname(ip)
            info = get_device_info(mac_address)
            device_type = detect_device_type(ip)
            has_open.append(ip)
            insert_scan_result(ip, port, name, device_type, info, mac_address, 'Open')

        for t in threads:
            t.join()

        maybe_dead = {x for x in ip_list if x not in has_open}
        threaded_ip_check(maybe_dead)

        print("DONE")

    def detect_device_type(ip_address):
        scanner = nmap.PortScanner()
        try:
            scanner.scan(ip_address, arguments='-O', timeout=10)
        except nmap.PortScannerError as e:
            return f"Scan error: {str(e)}"

        if ip_address not in scanner.all_hosts():
            return "Host unavailable"

        host = scanner[ip_address]
        output = []
        device_type = "Device type undetermined"

        if 'osmatch' in host and host['osmatch']:
            for osmatch in host['osmatch']:
                guess = f"OS Guess: {osmatch['name']}, Accuracy: {osmatch['accuracy']}%"
                output.append(guess)
                name_lower = osmatch['name'].lower()
                if 'windows' in name_lower:
                    device_type = "Windows PC or Server"
                elif 'linux' in name_lower:
                    device_type = "Linux machine or device"
                elif 'android' in name_lower:
                    device_type = "Android Phone"
                elif 'iphone' in name_lower:
                    device_type = "iPhone"
        return f"{device_type}. " + " ".join(output) if output else device_type

    def get_mac(ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        try:
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc if answered_list else "NA"
        except Exception as e:
            return f"Error retrieving MAC: {str(e)}"

    def get_device_info(mac_address):
        try:
            vendor = MacLookup().lookup(mac_address)
            return f"Manufacturer: {vendor}"
        except Exception as e:
            return f"Error: {str(e)}"

    def get_hostname(ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except socket.herror:
            return "Hostname not available"

    port_list = ports

    start_time = time.time()
    start_local_scan(num_threads)
    end_time = time.time()
    print(f"Total time taken: {end_time - start_time} seconds")
