import socket
import ipaddress
import threading
from queue import Queue
import csv


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))
    IP = s.getsockname()[0]
    s.close()
    return IP


def get_ip_range():
    local_ip = get_local_ip()
    ip_with_mask = str(local_ip) + "/24"
    network = ipaddress.ip_network(ip_with_mask, strict=False)
    return [str(ip) for ip in network.hosts()]


def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((ip, port))
        s.close()
        return ip, port, "Open"
    except (socket.timeout, socket.error):
        return None


def threader():
    while True:
        worker = q.get()
        result = scan_port(worker, 80)
        if result:
            results_queue.put(result)
        q.task_done()


def start_local_scan():
    for _ in range(num_threads):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
        threads.append(t)

    ip_list = get_ip_range()

    for ip in ip_list:
        q.put(ip)

    q.join()

    with open("open_ports.csv", mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Port", "Status"])

        while not results_queue.empty():
            writer.writerow(results_queue.get())

    for t in threads:
        t.join()


q = Queue()
results_queue = Queue()
threads = []
num_threads = 500