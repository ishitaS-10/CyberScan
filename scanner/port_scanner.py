import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((target, port))
        return port
    except:
        return None

def scan_ports(target):
    open_ports = []

    try:
        target_ip = socket.gethostbyname(target)
    except:
        return ["Invalid target"]

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target_ip, p), range(1, 1024))

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports