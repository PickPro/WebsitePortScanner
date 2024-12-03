port_info = {
    21: {
        "Use": "Transfers files between computers.",
        "Vulnerabilities": "Plaintext transmission (credentials and data). Anonymous access misconfiguration. Exploitable vulnerabilities in older FTP software.",
        "Attack Methods": "Sniffing credentials using tools like Wireshark. Exploiting default or weak credentials. Directory traversal attacks.",
        "Prevention": "Use FTPS or SFTP for encrypted communication. Disable anonymous FTP access. Use strong passwords and keep FTP software updated."
    },
    22: {
        "Use": "Secure remote login and file transfer.",
        "Vulnerabilities": "Brute force or dictionary attacks. Exploits of outdated SSH servers.",
        "Attack Methods": "Brute-forcing credentials using tools like Hydra. Man-in-the-Middle (MITM) attacks (if weak configurations).",
        "Prevention": "Use strong, unique passwords or SSH keys. Disable root login. Use Fail2Ban or equivalent to limit brute-force attempts."
    },
    23: {
        "Use": "Unencrypted remote login protocol.",
        "Vulnerabilities": "Transmits data, including credentials, in plaintext. Easily intercepted by attackers.",
        "Attack Methods": "Sniffing credentials. Brute force attacks on weak passwords.",
        "Prevention": "Disable Telnet; use SSH instead. Use firewalls to block Telnet traffic."
    },
    25: {
        "Use": "Email transmission.",
        "Vulnerabilities": "Open relays can be exploited for spam. Spoofing and phishing campaigns.",
        "Attack Methods": "Sending spam or phishing emails. Exploiting misconfigured servers.",
        "Prevention": "Configure the server to reject open relay. Use SPF, DKIM, and DMARC to prevent spoofing."
    },
    53: {
        "Use": "Resolves domain names to IP addresses.",
        "Vulnerabilities": "DNS cache poisoning. Amplification attacks (DDoS).",
        "Attack Methods": "Redirecting users to malicious domains. Amplifying DDoS traffic.",
        "Prevention": "Use DNSSEC to authenticate DNS data. Limit recursion and rate-limit DNS responses."
    },
    80: {
        "Use": "Unsecured web traffic.",
        "Vulnerabilities": "MITM attacks. Injection vulnerabilities like SQLi, XSS.",
        "Attack Methods": "Eavesdropping on data. Exploiting web app vulnerabilities.",
        "Prevention": "Use HTTPS instead. Regularly scan web apps for vulnerabilities."
    },
    110: {
        "Use": "Retrieves emails from servers (POP3).",
        "Vulnerabilities": "Plaintext transmission. Lack of authentication for email servers.",
        "Attack Methods": "Sniffing credentials. Session hijacking.",
        "Prevention": "Use secure protocols like POP3S. Employ strong passwords."
    },
    143: {
        "Use": "Retrieves emails from servers (IMAP).",
        "Vulnerabilities": "Plaintext transmission. Exploitable with weak configurations.",
        "Attack Methods": "Intercepting credentials. Exploiting misconfigured email servers.",
        "Prevention": "Use IMAPS for encryption. Ensure email server configuration is secure."
    },
    443: {
        "Use": "Encrypted web traffic.",
        "Vulnerabilities": "Weak SSL/TLS configurations. Vulnerable to Heartbleed, BEAST.",
        "Attack Methods": "Exploiting deprecated protocols. MITM if cert validation fails.",
        "Prevention": "Use strong SSL/TLS configs. Update certificates regularly."
    },
    445: {
        "Use": "File sharing and resource access.",
        "Vulnerabilities": "EternalBlue exploit. Ransomware propagation.",
        "Attack Methods": "Unauthorized SMB access. Malware spread.",
        "Prevention": "Disable SMBv1. Patch systems and use firewalls."
    },
    993: {
        "Use": "Encrypted email retrieval (IMAPS).",
        "Vulnerabilities": "Weak encryption configurations.",
        "Attack Methods": "Intercepting encrypted traffic. Exploiting vulnerable IMAP servers.",
        "Prevention": "Use strong encryption. Update IMAP server configurations."
    },
    995: {
        "Use": "Encrypted email retrieval (POP3S).",
        "Vulnerabilities": "Weak encryption configurations.",
        "Attack Methods": "Intercepting encrypted traffic.",
        "Prevention": "Use strong SSL/TLS configurations."
    },
    1433: {
        "Use": "Microsoft SQL Server.",
        "Vulnerabilities": "Brute force attacks. SQL injection.",
        "Attack Methods": "Brute-forcing credentials. Exploiting SQLi vulnerabilities.",
        "Prevention": "Use firewalls to restrict access. Enable SSL for database connections."
    },
    1521: {
        "Use": "Oracle Database server.",
        "Vulnerabilities": "Default or weak passwords. Exploitable vulnerabilities in old versions.",
        "Attack Methods": "Brute-forcing credentials. Exploiting misconfigurations.",
        "Prevention": "Update to secure versions. Use strong, unique passwords."
    },
    3306: {
        "Use": "MySQL database services.",
        "Vulnerabilities": "Weak authentication. SQL injection.",
        "Attack Methods": "Brute-forcing credentials. Exploiting SQLi vulnerabilities.",
        "Prevention": "Use firewalls to limit access. Enable SSL for database connections."
    },
    3389: {
        "Use": "Remote access to Windows machines.",
        "Vulnerabilities": "Brute force attacks. Vulnerabilities like BlueKeep.",
        "Attack Methods": "Brute-forcing credentials. Exploiting outdated RDP versions.",
        "Prevention": "Use strong passwords and MFA. Patch systems to mitigate BlueKeep."
    },
    5432: {
        "Use": "PostgreSQL database services.",
        "Vulnerabilities": "Weak passwords. Misconfigurations.",
        "Attack Methods": "Credential brute-forcing. Exploiting unpatched vulnerabilities.",
        "Prevention": "Use strong passwords. Limit access with firewalls."
    },
    5900: {
        "Use": "Remote desktop via VNC.",
        "Vulnerabilities": "Weak authentication. Exploitable software vulnerabilities.",
        "Attack Methods": "Brute-forcing credentials. Exploiting outdated VNC servers.",
        "Prevention": "Use strong passwords. Keep VNC software updated."
    },
    8080: {
        "Use": "Alternative HTTP port.",
        "Vulnerabilities": "Injection vulnerabilities. MITM attacks.",
        "Attack Methods": "Eavesdropping. Exploiting web app vulnerabilities.",
        "Prevention": "Use HTTPS. Regularly scan for vulnerabilities."
    },
    8443: {
        "Use": "Alternative HTTPS port.",
        "Vulnerabilities": "Weak SSL/TLS configurations.",
        "Attack Methods": "Exploiting deprecated protocols.",
        "Prevention": "Use strong SSL/TLS configurations."
    },
}
