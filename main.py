import socket
import ipaddress


def get_local_ip():
    # Connect to impossible ip to get our ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))
    IP = s.getsockname()[0]
    s.close()

    return IP

def get_ip_range():
    local_ip = get_local_ip()
    ip_with_mask = str(local_ip) + "/24"  # I am assuming we are using /24 here for simplicity but later i can add support for more although idk how to test that

    network = ipaddress.ip_network(ip_with_mask, strict=False)

    ip_range = [str(network.network_address + 1), str(network.broadcast_address - 1)]

    print(f"Network Address: {network.network_address}")
    print(f"First Usable IP: {network.network_address + 1}")
    print(f"Last Usable IP: {network.broadcast_address - 1}")
    print(f"Broadcast Address: {network.broadcast_address}")

    return ip_range


def scan_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.settimeout(1)

    try:
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, socket.error):
        return False


ip_list = get_ip_range()

base_ip = ip_list[0]

parts = base_ip.split('.')
base_ip = '.'.join(parts[:-1]) + '.'
print(base_ip)

for i in range (1, 255):
    ip_address = base_ip + str(i)
    port_to_scan = 80

    if scan_port(ip_address, port_to_scan):
        print(f"Port {port_to_scan} is open on {ip_address}")


