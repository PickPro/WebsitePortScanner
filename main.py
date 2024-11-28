import streamlit as st
import socket
from datetime import datetime
from urllib.parse import urlparse

def scanner(host):
    # Same ports and port_info dictionary as in your existing code.
    ports = [80, 21, 22, 23, 25, 53, 137, 139, 445, 443, 8080, 8443, 1433, 1434, 3306, 3389]
    port_info = {
    21: {
        "Name": "FTP - File Transfer Protocol",
        "Use": "Transfers files between computers.",
        "Vulnerabilities": [
            "Plaintext transmission (credentials and data).",
            "Anonymous access misconfiguration.",
            "Exploitable vulnerabilities in older FTP software."
        ],
        "Attack Methods": [
            "Sniffing credentials using tools like Wireshark.",
            "Exploiting default or weak credentials.",
            "Directory traversal attacks to access unauthorized files."
        ],
        "Prevention": [
            "Use FTPS or SFTP for encrypted communication.",
            "Disable anonymous FTP access.",
            "Use strong, unique passwords and keep FTP software updated."
        ]
    },
    22: {
        "Name": "SSH - Secure Shell",
        "Use": "Secure remote login and file transfer.",
        "Vulnerabilities": [
            "Brute force or dictionary attacks.",
            "Exploits of outdated SSH servers."
        ],
        "Attack Methods": [
            "Brute-forcing credentials using tools like Hydra.",
            "Man-in-the-Middle (MITM) attacks (if weak configurations)."
        ],
        "Prevention": [
            "Use strong, unique passwords or SSH keys.",
            "Disable root login.",
            "Use fail2ban or equivalent to limit brute-force attempts."
        ]
    },
    23: {
        "Name": "Telnet",
        "Use": "Unencrypted remote login protocol.",
        "Vulnerabilities": [
            "Transmits data, including credentials, in plaintext.",
            "Easily intercepted by attackers."
        ],
        "Attack Methods": [
            "Sniffing credentials.",
            "Brute force attacks on weak passwords."
        ],
        "Prevention": [
            "Disable Telnet; use SSH instead.",
            "Use firewalls to block Telnet traffic."
        ]
    },
    25: {
        "Name": "SMTP - Simple Mail Transfer Protocol",
        "Use": "Email transmission.",
        "Vulnerabilities": [
            "Open relays can be exploited for spam.",
            "Spoofing and phishing campaigns."
        ],
        "Attack Methods": [
            "Sending spam or phishing emails.",
            "Exploiting misconfigured servers."
        ],
        "Prevention": [
            "Configure the server to reject open relay.",
            "Use SPF, DKIM, and DMARC to prevent spoofing."
        ]
    },
    53: {
        "Name": "DNS - Domain Name System",
        "Use": "Resolves domain names to IP addresses.",
        "Vulnerabilities": [
            "DNS cache poisoning.",
            "Amplification attacks (DDoS)."
        ],
        "Attack Methods": [
            "Redirecting users to malicious domains.",
            "Amplifying DDoS traffic."
        ],
        "Prevention": [
            "Use DNSSEC to authenticate DNS data.",
            "Limit recursion and rate-limit DNS responses."
        ]
    },
    80: {
        "Name": "HTTP - Hypertext Transfer Protocol",
        "Use": "Unsecured web traffic.",
        "Vulnerabilities": [
            "MITM attacks.",
            "Injection vulnerabilities (SQLi, XSS)."
        ],
        "Attack Methods": [
            "Eavesdropping on data in transit.",
            "Exploiting vulnerable web applications."
        ],
        "Prevention": [
            "Use HTTPS instead of HTTP.",
            "Regularly scan web applications for vulnerabilities."
        ]
    },
    137: {
        "Name": "NetBIOS Name Service",
        "Use": "Network file and printer sharing.",
        "Vulnerabilities": [
            "Information disclosure.",
            "Exploitable in SMB attacks."
        ],
        "Attack Methods": [
            "Enumeration of network resources.",
            "Lateral movement in networks."
        ],
        "Prevention": [
            "Disable NetBIOS if not needed.",
            "Use a firewall to block external access to these ports."
        ]
    },
    139: {
        "Name": "NetBIOS Session Service",
        "Use": "Network file and printer sharing.",
        "Vulnerabilities": [
            "Information disclosure.",
            "Exploitable in SMB attacks."
        ],
        "Attack Methods": [
            "Enumeration of network resources.",
            "Lateral movement in networks."
        ],
        "Prevention": [
            "Disable NetBIOS if not needed.",
            "Use a firewall to block external access to these ports."
        ]
    },
    445: {
        "Name": "SMB - Server Message Block",
        "Use": "File sharing and network resource access.",
        "Vulnerabilities": [
            "EternalBlue and related exploits.",
            "Ransomware propagation (e.g., WannaCry)."
        ],
        "Attack Methods": [
            "Exploiting SMB vulnerabilities to gain unauthorized access.",
            "Spreading malware across networks."
        ],
        "Prevention": [
            "Disable SMBv1; use SMBv2 or SMBv3.",
            "Patch systems regularly.",
            "Use firewalls to block unnecessary access."
        ]
    },
    443: {
        "Name": "HTTPS - HTTP Secure",
        "Use": "Encrypted web traffic.",
        "Vulnerabilities": [
            "Poor SSL/TLS configurations.",
            "Vulnerable to certain attacks (e.g., Heartbleed, BEAST)."
        ],
        "Attack Methods": [
            "Exploiting deprecated protocols and ciphers.",
            "MITM if certificate validation fails."
        ],
        "Prevention": [
            "Use strong SSL/TLS configurations.",
            "Regularly update server certificates."
        ]
    },
    8080: {
        "Name": "Alternate HTTP Port",
        "Use": "Alternative web traffic port.",
        "Vulnerabilities": [
            "Same as HTTP.",
            "Often used by proxy or web server admin interfaces."
        ],
        "Attack Methods": [
            "Attacking poorly secured admin interfaces.",
            "Injection attacks."
        ],
        "Prevention": [
            "Use strong authentication for admin interfaces.",
            "Regularly update web server software."
        ]
    },
    8443: {
        "Name": "Alternate HTTPS Port",
        "Use": "Alternative encrypted web traffic port.",
        "Vulnerabilities": [
            "Same as HTTPS.",
            "Often used by proxy or web server admin interfaces."
        ],
        "Attack Methods": [
            "Attacking poorly secured admin interfaces.",
            "Injection attacks."
        ],
        "Prevention": [
            "Use strong authentication for admin interfaces.",
            "Regularly update web server software."
        ]
    },
    1433: {
        "Name": "Microsoft SQL Server",
        "Use": "Database services.",
        "Vulnerabilities": [
            "Weak credentials.",
            "SQL injection."
        ],
        "Attack Methods": [
            "Brute-force attacks.",
            "Exploiting SQL injection to manipulate databases."
        ],
        "Prevention": [
            "Use strong credentials and enforce encryption.",
            "Restrict access to database ports."
        ]
    },
    1434: {
        "Name": "Microsoft SQL Monitor",
        "Use": "Database discovery and monitoring.",
        "Vulnerabilities": [
            "Information disclosure.",
            "Buffer overflow vulnerabilities."
        ],
        "Attack Methods": [
            "Enumeration of SQL servers.",
            "Exploiting buffer overflow vulnerabilities."
        ],
        "Prevention": [
            "Disable unnecessary services.",
            "Keep SQL Server software updated."
        ]
    },
    3306: {
        "Name": "MySQL Database",
        "Use": "MySQL database services.",
        "Vulnerabilities": [
            "Weak authentication.",
            "SQL injection."
        ],
        "Attack Methods": [
            "Brute-forcing MySQL credentials.",
            "Exploiting SQL injection vulnerabilities."
        ],
        "Prevention": [
            "Use firewalls to limit access.",
            "Enable SSL for database connections.",
            "Use strong, unique passwords."
        ]
    },
    3389: {
        "Name": "RDP - Remote Desktop Protocol",
        "Use": "Remote access to Windows machines.",
        "Vulnerabilities": [
            "Brute force or credential stuffing.",
            "BlueKeep vulnerability."
        ],
        "Attack Methods": [
            "Brute-forcing RDP credentials.",
            "Exploiting vulnerabilities in outdated RDP software."
        ],
        "Prevention": [
            "Use strong passwords and multi-factor authentication (MFA).",
            "Patch systems to mitigate BlueKeep.",
            "Limit RDP access using firewalls or VPNs."
        ]
    }
}

    report = ""
    host_ip = socket.gethostbyname(host)
    
    report += f"Scan Report for {host}\n\n"
    report += f"\n**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

    report += f"\n**IP Address:** {host_ip}\n"
    report += "---\n"
    
    with st.spinner("Scanning in progress... Please wait."):
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host_ip, port))
            if result == 0:
                info = port_info.get(port, {})
                report += f"### Port {port} ({info.get('Name', 'Unknown Service')}) is OPEN\n"
                report += f"**Use:** {info.get('Use', 'No information available.')}\n\n"
                report += "**Vulnerabilities:**\n"
                for vuln in info.get("Vulnerabilities", ["No vulnerabilities listed."]):
                    report += f"- {vuln}\n"
                report += "\n**Attack Methods:**\n"
                for attack in info.get("Attack Methods", ["No attack methods listed."]):
                    report += f"- {attack}\n"
                report += "\n**Prevention Methods:**\n"
                for prevent in info.get("Prevention", ["No prevention methods listed."]):
                    report += f"- {prevent}\n"
                report += "---\n"
            sock.close()

    return report

# Streamlit App Interface
st.title("Port Scanner")
st.subheader("Scan if a site is vulnerable!")

hostname_input = st.text_input("Enter the hostname or IP address", placeholder="example.com")
def preprocess_hostname(hostname):
    parsed_url = urlparse(hostname)
    if parsed_url.netloc:
        return parsed_url.netloc
    return parsed_url.path

if st.button("Start Scan"):
    try:
        hostname = preprocess_hostname(hostname_input)

        t1 = datetime.now()
        report = scanner(hostname)
        t2 = datetime.now()
        time_taken = t2 - t1

        if report:
            st.success(f"Scan completed in {time_taken}. Here is the security report:")
            st.markdown(report, unsafe_allow_html=True)
        else:
            st.warning("No open ports detected from the scanned list.")

    except socket.gaierror:
        st.error("Invalid hostname. Please try again.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
