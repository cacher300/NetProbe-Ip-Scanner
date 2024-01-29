import queue
import socket
import ipaddress
import threading
from queue import Queue
import sys
import time
from sql_setup import setup_database, insert_scan_result

# Global event to signal threads to stop
stop_event = threading.Event()

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

def scan_port(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return ip, port
    except (socket.timeout, socket.error):
        return None

def threader():
    while not stop_event.is_set():
        try:
            worker = q.get(timeout=0.5)
        except queue.Empty:  # Correct reference to the Empty exception
            continue

        for port in port_list:
            if stop_event.is_set():
                break
            result = scan_port(worker, port, timeout=3)
            if result:
                results_queue.put(result)
        q.task_done()


def start_local_scan(threads_num):
    setup_database()  # Set up the database and table

    for _ in range(threads_num):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
        threads.append(t)

    ip_list = get_ip_range()

    for ip in ip_list:
        q.put(ip)

    start_time = time.time()
    while not all(t.is_alive() for t in threads) or not q.empty():
        if time.time() - start_time > 10000000000:
            stop_event.set()
            break
        time.sleep(1)

    stop_event.set()

    while not results_queue.empty():
        ip, port = results_queue.get()
        insert_scan_result(ip, port)

    for t in threads:
        t.join()
    print("DONE")


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
