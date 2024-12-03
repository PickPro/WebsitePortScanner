from scapy.all import IP, TCP, sr1

# Function to perform SYN scan and display results
def syn_scan(target, ports):
    print(f"Scanning {target} for open ports...\n")
    open_ports = []

    for port in ports:
        syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            open_ports.append(port)
            print(f"Port {port} is open.")

    if not open_ports:
        print("No open ports found.")
    else:
        print("\nScan complete. Open ports:", open_ports)

# Target and ports
target_url = "scanme.nmap.org"
ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

# Perform the scan
syn_scan(target_url, ports)
