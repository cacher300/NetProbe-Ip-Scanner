import socket
import ipaddress

def get_local_ip():
    # Connect to impossible ip to get our ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))
    IP = s.getsockname()[0]
    s.close()

    return IP


local_ip = get_local_ip()
ip_with_mask = str(local_ip) + "/24"  # I am assuming we are using /24 here for simplicity but later i can add support for more although idk how to test that

network = ipaddress.ip_network(ip_with_mask, strict=False)

ip_range = [network.network_address + 1, network.broadcast_address - 1]
