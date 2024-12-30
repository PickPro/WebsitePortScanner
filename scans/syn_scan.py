# syn_scan.py

from scapy.all import IP, TCP, sr1
from port_info import port_info

def syn_scan(target, ports, progress_callback=None):
    open_ports = []
    total_ports = len(ports)

    for idx, port in enumerate(ports):
        syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            port_details = {
                'port': port,
                'status': 'open',
                'protocol': 'Syn',
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

        if progress_callback:
            progress_callback(idx + 1, total_ports)

    return open_ports