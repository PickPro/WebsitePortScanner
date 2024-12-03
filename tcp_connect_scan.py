import socket

# Function for TCP Connect Scan
def tcp_connect_scan(target, ports):
    print(f"Performing TCP Connect Scan on {target}...\n")
    open_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:  # Port is open
                    open_ports.append(port)
                    print(f"Port {port} is open.\n")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    if not open_ports:
        print("No open ports found.\n")
    else:
        print("Scan complete. Open ports:", open_ports)

# Target and ports
target_url = "scanme.nmap.org"
ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

# Perform the TCP Connect Scan
tcp_connect_scan(target_url, ports)
