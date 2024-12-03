import socket
# Comprehensive port information dictionary (as defined earlier)
port_info = {
    21: {"Use": "FTP", "Vulnerabilities": "Plaintext transmission", "Attack Methods": "Credential sniffing", "Prevention": "Use FTPS"},
    22: {"Use": "SSH", "Vulnerabilities": "Brute force attacks", "Attack Methods": "Credential brute-forcing", "Prevention": "Use SSH keys"},
    23: {"Use": "Telnet", "Vulnerabilities": "Plaintext transmission", "Attack Methods": "Eavesdropping", "Prevention": "Disable Telnet"},
    25: {"Use": "SMTP", "Vulnerabilities": "Open relay", "Attack Methods": "Spam emails", "Prevention": "Configure mail server properly"},
    53: {"Use": "DNS", "Vulnerabilities": "DNS cache poisoning", "Attack Methods": "Redirecting traffic", "Prevention": "Use DNSSEC"},
    80: {"Use": "HTTP", "Vulnerabilities": "MITM attacks", "Attack Methods": "Data eavesdropping", "Prevention": "Use HTTPS"},
    110: {"Use": "POP3", "Vulnerabilities": "Plaintext credentials", "Attack Methods": "Credential sniffing", "Prevention": "Use POP3S"},
    143: {"Use": "IMAP", "Vulnerabilities": "Plaintext credentials", "Attack Methods": "Intercepting credentials", "Prevention": "Use IMAPS"},
    443: {"Use": "HTTPS", "Vulnerabilities": "Weak TLS", "Attack Methods": "Protocol exploitation", "Prevention": "Use strong TLS"},
    445: {"Use": "SMB", "Vulnerabilities": "Ransomware propagation", "Attack Methods": "Unauthorized SMB access", "Prevention": "Patch systems"},
    993: {"Use": "IMAPS", "Vulnerabilities": "Weak encryption", "Attack Methods": "Traffic interception", "Prevention": "Use strong encryption"},
    995: {"Use": "POP3S", "Vulnerabilities": "Weak encryption", "Attack Methods": "Intercepting traffic", "Prevention": "Use TLS"},
    1433: {"Use": "MS SQL", "Vulnerabilities": "SQL injection", "Attack Methods": "Credential brute-forcing", "Prevention": "Secure DB access"},
    1521: {"Use": "Oracle DB", "Vulnerabilities": "Weak passwords", "Attack Methods": "Exploiting DB vulnerabilities", "Prevention": "Strong passwords"},
    3306: {"Use": "MySQL", "Vulnerabilities": "SQL injection", "Attack Methods": "Weak authentication", "Prevention": "Use SSL"},
    3389: {"Use": "RDP", "Vulnerabilities": "Brute force attacks", "Attack Methods": "BlueKeep vulnerability", "Prevention": "Use MFA"},
    5432: {"Use": "PostgreSQL", "Vulnerabilities": "Weak passwords", "Attack Methods": "Credential brute-forcing", "Prevention": "Use firewalls"},
    5900: {"Use": "VNC", "Vulnerabilities": "Weak authentication", "Attack Methods": "Exploiting outdated software", "Prevention": "Update software"},
    8080: {"Use": "HTTP Alt", "Vulnerabilities": "Injection vulnerabilities", "Attack Methods": "Exploiting web apps", "Prevention": "Use HTTPS"},
    8443: {"Use": "HTTPS Alt", "Vulnerabilities": "Weak TLS", "Attack Methods": "Deprecated protocols", "Prevention": "Strong TLS"},
}


# Function to perform UDP Scan
def udp_scan(target, ports):
    print(f"Performing UDP Scan on {target}...\n")
    open_ports = []
    filtered_ports = []
    closed_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                # Sending a generic UDP packet
                sock.sendto(b"\x00", (target, port))
                try:
                    # Waiting for a response
                    data, _ = sock.recvfrom(1024)
                    open_ports.append(port)
                    print(f"Port {port} is OPEN (Received response).")
                except socket.timeout:
                    # Port might be filtered or open but no response
                    filtered_ports.append(port)
                    print(f"Port {port} is FILTERED (No response).")
        except socket.error as e:
            # ICMP unreachable indicates closed port
            if "ICMP" in str(e) or e.errno == 111:  # Connection refused
                closed_ports.append(port)
                print(f"Port {port} is CLOSED (ICMP unreachable or connection refused).")
            else:
                print(f"Error scanning port {port}: {e}")

    print("\n--- Scan Summary ---")
    print(f"Open Ports: {open_ports}")
    print(f"Filtered Ports: {filtered_ports}")
    print(f"Closed Ports: {closed_ports}")

    for port in open_ports:
        if port in port_info:
            info = port_info[port]
            print(f"\nPort {port}:")
            print(f"Use: {info['Use']}")
            print(f"Vulnerabilities: {info['Vulnerabilities']}")
            print(f"Attack Methods: {info['Attack Methods']}")
            print(f"Prevention: {info['Prevention']}")

# Target and ports
target_url = "scanme.nmap.org"
ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

# Perform the UDP Scan
udp_scan(target_url, ports)
