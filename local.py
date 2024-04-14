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
        return ip, port
    except (socket.timeout, socket.error):
        return None


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
            worker = q.get(timeout=0.5)
        except Empty:
            continue

        for port in port_list:
            if stop_event.is_set():
                break
            result = scan_port(worker, port, timeout=3)
            if result:
                results_queue.put(result)
        q.task_done()


def start_local_scan(threads_num):
    setup_database()
    has_open = []

    for _ in range(threads_num):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
        print('1')
        threads.append(t)
        print('2')

    ip_list = get_ip_range()

    for ip in ip_list:
        print('3')
        q.put(ip)

    q.join()
    print('4')
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
    scanner.scan(ip_address, arguments='-O')
    if ip_address not in scanner.all_hosts():
        return "Host unavailable"

    host = scanner[ip_address]
    output = []
    device_type = "Device type undetermined"

    if 'osmatch' in host and host['osmatch']:
        for osmatch in host['osmatch']:
            guess = f"OS Guess: {osmatch['name']}, Accuracy: {osmatch['accuracy']}%"
            output.append(guess)
            # You can infer device types by the name of the OS
            if 'windows' in osmatch['name'].lower():
                device_type = "Windows PC or Server"
            elif 'linux' in osmatch['name'].lower():
                device_type = "Linux machine or device"
            elif 'android' in osmatch['name'].lower():
                device_type = "Android Phone"
            elif 'iphone' in osmatch['name'].lower():
                device_type = "iPhone"

    if output:
        return f"{device_type}. " + " ".join(output)
    else:
        return device_type


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc if answered_list else "NA"


def get_device_info(mac_address):
    p = manuf.MacParser()

    manufacturer = p.get_manuf(mac_address)
    description = p.get_manuf_long(mac_address)

    return f"Manufacturer: {manufacturer}, Description: {description}"


def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "NA"


q = Queue()
results_queue = Queue()
threads = []

scan_type = sys.argv[1]
num_threads = int(sys.argv[2])
ip_range = sys.argv[3]
length = int(sys.argv[4])


port_list = []
i = 0
while i < int(length):
    port_list.append(sys.argv[i+4])
    i += 1

port_list = [int(sys.argv[i + 5]) for i in range(length)]

q = Queue()
results_queue = Queue()
threads = []

start_local_scan(int(num_threads))
