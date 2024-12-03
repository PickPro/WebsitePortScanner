# udp_scan.py

import socket
from port_info import port_info

def udp_scan(target, ports, progress_callback=None):
    open_ports = []
    total_ports = len(ports)

    for idx, port in enumerate(ports):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(b"\x00", (target, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    port_details = {
                        'port': port,
                        'status': 'open',
                        'protocol': 'UDP',
                        'service': port_info.get(port, {}).get('Use', 'Unknown'),
                        'vulnerabilities': port_info.get(port, {}).get('Vulnerabilities', 'N/A'),
                        'attack_methods': port_info.get(port, {}).get('Attack Methods', 'N/A'),
                        'prevention': port_info.get(port, {}).get('Prevention', 'N/A')
                    }
                    open_ports.append(port_details)
                except socket.timeout:
                    pass  # No response; port might be filtered or open without response
        except Exception:
            pass  # Handle exceptions as needed

        if progress_callback:
            progress_callback(idx + 1, total_ports)

    return open_ports