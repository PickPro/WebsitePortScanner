# tcp_connect_scan.py

import socket
from port_info import port_info

def tcp_connect_scan(target, ports, progress_callback=None):
    open_ports = []
    total_ports = len(ports)

    for idx, port in enumerate(ports):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:  # Port is open
                    port_details = {
                        'port': port,
                        'status': 'open',
                        'protocol': 'Tcp',
                        'service': port_info.get(port, {}).get('Use', 'Unknown'),
                        'vulnerabilities': port_info.get(port, {}).get('Vulnerabilities', 'N/A'),
                        'attack_methods': port_info.get(port, {}).get('Attack Methods', 'N/A'),
                        'prevention': port_info.get(port, {}).get('Prevention', 'N/A'),
                        'real-worldexample': port_info.get(port, {}).get('Real-World Example', 'N/A'),
                        'commonServices': port_info.get(port, {}).get('Common Services', 'N/A'),
                        'misconfigurations': port_info.get(port, {}).get('Misconfigurations', 'N/A'),
                        'securityfeatures': port_info.get(port, {}).get('Security Features', 'N/A')
                    }
                    open_ports.append(port_details)
        except Exception:
            pass  # Handle exceptions as needed

        if progress_callback:
            progress_callback(idx + 1, total_ports)

    return open_ports