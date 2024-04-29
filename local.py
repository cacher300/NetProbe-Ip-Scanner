import ipaddress
import threading
from queue import Queue, Empty
import sys
from local_sql_setup import setup_database, insert_scan_result
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sr1, conf
from scapy.layers.inet import IP, ICMP
import manuf
import nmap
import socket
import time


stop_event = threading.Event()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))
    ip = s.getsockname()[0]
    s.close()
    return ip

def get_ip_range():
    local_ip = get_local_ip()
    ip_with_mask = str(local_ip) + "/24"
    network = ipaddress.ip_network(ip_with_mask, strict=False)
    return [str(ip) for ip in network.hosts()]

def scan_port(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True, (ip, port)
    except (socket.timeout, socket.error):
        return False, None

def is_ip_alive(ip):
    conf.verb = 0
    icmp = IP(dst=ip)/ICMP()
    response = sr1(icmp, timeout=1, verbose=0)
    return response is not None

def check_ip(ip):
    if is_ip_alive(ip):
        print(ip)
        mac_address = get_mac(ip)
        name = get_hostname(ip)
        if mac_address != 'NA':
            device_type = get_device_info(mac_address)
        else:
            device_type = 'NA'
        os = detect_device_type(ip)
        insert_scan_result(ip, 'NA', name, device_type, os, mac_address, 'Alive')

def threaded_ip_check(ip_list):
    threads = []
    for ip in ip_list:
        thread = threading.Thread(target=check_ip, args=(ip,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

def threader():
    while not stop_event.is_set():
        try:
            worker = q.get(timeout=1)  # Adjust timeout as needed
        except Empty:
            #print("Queue is empty, thread is idling...")
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
    print("1")

    ip_list = get_ip_range()
    for ip in ip_list:
        q.put(ip)
    print("2")

    q.join()
    stop_event.set()
    print("3")

    while not results_queue.empty():
        ip, port = results_queue.get()
        mac_address = get_mac(ip)
        name = get_hostname(ip)
        info = get_device_info(mac_address)
        device_type = detect_device_type(ip)
        has_open.append(ip)
        insert_scan_result(ip, port, name, device_type, info, mac_address, 'Open')
    print("4")

    for t in threads:
        t.join()
    print("5")

    maybe_dead = {x for x in ip_list if x not in has_open}
    threaded_ip_check(maybe_dead)
    print("6")

    print("DONE")


def detect_device_type(ip_address):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip_address, arguments='-O')
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
    if mac_address == "NA":
        return "MAC address not available"

    p = manuf.MacParser()
    try:
        manufacturer = p.get_manuf(mac_address)
        description = p.get_manuf_long(mac_address)
        return f"Manufacturer: {manufacturer}, Description: {description}"
    except ValueError as e:
        return f"Error: {str(e)}"


def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Hostname not available"


q = Queue()
results_queue = Queue()
threads = []

scan_type = sys.argv[1]
num_threads = int(sys.argv[2])
ip_range = sys.argv[3]
length = int(sys.argv[4])

print(num_threads)


port_list = []
i = 0
while i < int(length):
    port_list.append(sys.argv[i+4])
    i += 1

port_list = [int(sys.argv[i + 5]) for i in range(length)]

print(port_list)
q = Queue()
results_queue = Queue()
threads = []
print("hello")
start_time = time.time()  # Record the start time
start_local_scan(num_threads)  # Assume sys.argv[2] is the number of threads
end_time = time.time()  # Record the end time
print(f"Total time taken: {end_time - start_time} seconds")
