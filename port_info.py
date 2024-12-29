port_info = {
    21: {
        "Use": "Transfers files between computers.",
        "Vulnerabilities": "Plaintext transmission (credentials and data). Anonymous access misconfiguration. Exploitable vulnerabilities in older FTP software.",
        "Attack Methods": "Sniffing credentials using tools like Wireshark. Exploiting default or weak credentials. Directory traversal attacks.",
        "Prevention": "Use FTPS or SFTP for encrypted communication. Disable anonymous FTP access. Use strong passwords and keep FTP software updated.",
        "Real-World Example":"Exploitation of ProFTPD (allowed remote code execution)",
        "Common Services":"ProFTPD, vsftpd.",
        "Misconfigurations":"Allowing anonymous login without restrictions.",
        "Security Features":"TLS/SSL for encryption"
    },
    22: {
        "Use": "Secure remote login and file transfer.",
        "Vulnerabilities": "Brute force or dictionary attacks. Exploits of outdated SSH servers.",
        "Attack Methods": "Brute-forcing credentials using tools like Hydra. Man-in-the-Middle (MITM) attacks (if weak configurations).",
        "Prevention": "Use strong, unique passwords or SSH keys. Disable root login. Use Fail2Ban or equivalent to limit brute-force attempts.",
        "Real-World Example":"CVE-2020-15778 in OpenSSH allowed command injection.",
        "Common Services":"OpenSSH, PuTTY.",
        "Misconfigurations":"Allowing weak passwords or keys. Allowing root login or using outdated cryptographic protocols.",
        "Security Features":"Key exchange protocols (e.g., Diffie-Hellman, Ellipt"
    },
    23: {
        "Use": "Unencrypted remote login protocol.",
        "Vulnerabilities": "Transmits data, including credentials, in plaintext. Easily intercepted by attackers.",
        "Attack Methods": "Sniffing credentials. Brute force attacks on weak passwords.",
        "Prevention": "Disable Telnet; use SSH instead. Use firewalls to block Telnet traffic.",
        "Real-World Example":"Telnet is often used for educational purposes. Attackers exploited Telnet to build botnets.",
        "Common Services":"Telnet daemon.",
        "Misconfigurations":"Allowing Telnet access without restrictions. Using default or weak credentials.",
        "Security Features":"Replace with encrypted protocols like SSH."
    },
    25: {
        "Use": "Email transmission.",
        "Vulnerabilities": "Open relays can be exploited for spam. Spoofing and phishing campaigns.",
        "Attack Methods": "Sending spam or phishing emails. Exploiting misconfigured servers.",
        "Prevention": "Configure the server to reject open relay. Use SPF, DKIM, and DMARC to prevent spoofing. Disable open relay and implement authentication.",
        "Real-World Example":"Open relay exploitation led to a massive spam campaign.",
        "Common Services":"Postfix, Exim, Sendmail.",
        "Misconfigurations":"Use of open relays. Use of weak passwords or authentication methods, Leaving the server as an open relay.",
        "Security Features":"Authentication, SPF, DKIM, DMARC, TLS encryption."
    },
    53: {
        "Use": "Resolves domain names to IP addresses.",
        "Vulnerabilities": "DNS cache poisoning. Amplification attacks (DDoS).",
        "Attack Methods": "Redirecting users to malicious domains. Amplifying DDoS traffic.",
        "Prevention": "Use DNSSEC to authenticate DNS data. Limit recursion and rate-limit DNS responses.",
        "Real-World Example":"Kaminsky exploit for DNS cache poisoning led to a massive DDoS attack.",
        "Common Services":"BIND, Unbound.",
        "Misconfigurations":"Allowing recursion without restrictions. Not implementing DNSSEC, Recursive queries enabled for public use.",
        "Security Features":"DNSSEC for integrity, DNS over HTTPS (DoH), DNS over TLS (DoT)."
    },
    80: {
        "Use": "Unsecured web traffic.",
        "Vulnerabilities": "MITM attacks. Injection vulnerabilities like SQLi, XSS.",
        "Attack Methods": "Eavesdropping on data. Exploiting web app vulnerabilities.",
        "Prevention": "Use HTTPS instead. Regularly scan web apps for vulnerabilities.",
        "Real-World Example":"Heartbleed bug in OpenSSL allowed eavesdropping.",
        "Common Services":"Apache, Nginx.",
        "Misconfigurations":"Not using HTTPS. Not keeping software up to date.",
        "Security Features":"HTTPS, Web Application Firewall (WAF), Regular security audits."
    },
    110: {
        "Use": "Retrieves emails from servers (POP3).",
        "Vulnerabilities": "Plaintext transmission. Lack of authentication for email servers.",
        "Attack Methods": "Sniffing credentials. Session hijacking.",
        "Prevention": "Use secure protocols like POP3S. Employ strong passwords.",
        "Real-World Example":"POP3 was used for email retrieval, but it was not secure",
        "Common Services":"POP3.",
        "Misconfigurations":"Use of POP3 without encryption. Weak passwords or authentication methods.",
        "Security Features":"POP3S, IMAP, Authentication, Encryption."
    },
    143: {
        "Use": "Retrieves emails from servers (IMAP).",
        "Vulnerabilities": "Plaintext transmission. Exploitable with weak configurations.",
        "Attack Methods": "Intercepting credentials. Exploiting misconfigured email servers.",
        "Prevention": "Use IMAPS for encryption. Ensure email server configuration is secure.",
        "Real-World Example":"IMAP was used for email retrieval, but it was not secure",
        "Common Services":"IMAP.",
        "Misconfigurations":"Use of IMAP without encryption. Weak passwords or authentication methods.",
        "Security Features":"IMAPS, Authentication, Encryption."
    },
    443: {
        "Use": "Encrypted web traffic.",
        "Vulnerabilities": "Weak SSL/TLS configurations. Vulnerable to Heartbleed, BEAST.",
        "Attack Methods": "Exploiting deprecated protocols. MITM if cert validation fails.",
        "Prevention": "Use strong SSL/TLS configs. Update certificates regularly.",
        "Real-World Example":"Heartbleed bug in OpenSSL to expose sensitive data.",
        "Common Services":"Apache, Nginx, IIS.",
        "Misconfigurations":"Allowing outdated SSL versions like SSLv3.",
        "Security Features":"Encypted communication using TLS."
    },
    445: {
        "Use": "File sharing and resource access.",
        "Vulnerabilities": "EternalBlue exploit. Ransomware propagation.",
        "Attack Methods": "Unauthorized SMB access. Malware spread.",
        "Prevention": "Disable SMBv1. Patch systems and use firewalls.",
        "Real-World Example":"EternalBlue exploit used in WannaCry ransomware attack. The WannaCry ransomware used SMB vulnerabilities to spread globally.",
        "Common Services":"Windows SMB.",
        "Misconfigurations":"Enabling SMBv1 without restrictions. Not patching systems.",
        "Security Features":"Firewalls, Patch management, Network segmentation, Improved authentication in SMBv3."
    },
    993: {
        "Use": "Encrypted email retrieval (IMAPS).",
        "Vulnerabilities": "Weak encryption configurations.",
        "Attack Methods": "Intercepting encrypted traffic. Exploiting vulnerable IMAP servers.",
        "Prevention": "Use strong encryption. Update IMAP server configurations.",
        "Real-World Example":"Attackers intercepting IMAP connections with weak SSL.",
        "Common Services":"Dovecot, Microsoft Exchange.",
        "Misconfigurations":"Use of weak encryption. Misconfigured IMAP servers, allowing plaintext connections.",
        "Security Features":"IMAPS, Authentication, Encryption, strong TLS encryption."
    },
    995: {
        "Use": "Encrypted email retrieval (POP3S).",
        "Vulnerabilities": "Weak encryption configurations.",
        "Attack Methods": "Intercepting encrypted traffic.",
        "Prevention": "Use strong SSL/TLS configurations.",
        "Real-World Example":"Attackers intercepting POP3S connections with weak SSL.",
        "Common Services":"POP3S, Dovecot, Outlook, Thunderbird.",
        "Misconfigurations":"Use of weak encryption. Misconfigured POP3S servers, Leaving older POP3 implementations enabled.",
        "Security Features":"POP3S, Authentication, Encryption,Mandatory strong TLS encryption."
    },
    1433: {
        "Use": "Microsoft SQL Server.",
        "Vulnerabilities": "Brute force attacks. SQL injection.",
        "Attack Methods": "Brute-forcing credentials. Exploiting SQLi vulnerabilities.",
        "Prevention": "Use firewalls to restrict access. Enable SSL for database connections.",
        "Real-World Example":"SQL injection attacks on SQL Server.",
        "Common Services":"Microsoft SQL Server.",
        "Misconfigurations":"Enabling SQL Server to listen on all interfaces. Not using strong passwords",
        "Security Features":"Firewalls, Authentication, Encryption, Regular backups, Patch management."
    },
    1521: {
        "Use": "Oracle Database server.",
        "Vulnerabilities": "Default or weak passwords. Exploitable vulnerabilities in old versions.",
        "Attack Methods": "Brute-forcing credentials. Exploiting misconfigurations.",
        "Prevention": "Update to secure versions. Use strong, unique passwords.",
        "Real-World Example":"Oracle database vulnerabilities exploited by attackers.",
        "Common Services":"Oracle Database.",
        "Misconfigurations":"Using default or weak passwords. Not updating to secure versions.",
        "Security Features":"Firewalls, Authentication, Encryption, Regular backups, Patch management."
    },
    3306: {
        "Use": "MySQL database services.",
        "Vulnerabilities": "Weak authentication. SQL injection.",
        "Attack Methods": "Brute-forcing credentials. Exploiting SQLi vulnerabilities.",
        "Prevention": "Use firewalls to limit access. Enable SSL for database connections.",
        "Real-World Example":"SQL injection attacks on MySQL, Database breaches due to poorly secured MySQL servers.",
        "Common Services":"MySQL, MariaDB.",
        "Misconfigurations":"Enabling MySQL to listen on all interfaces. Allowing public access to port 3396.",
        "Security Features":"Firewalls, Authentication, Encryption, Regular backups, Patch management, SSL/TLS encyption for client connections."
    },
    3389: {
        "Use": "Remote access to Windows machines.",
        "Vulnerabilities": "Brute force attacks. Vulnerabilities like BlueKeep.",
        "Attack Methods": "Brute-forcing credentials. Exploiting outdated RDP versions.",
        "Prevention": "Use strong passwords and MFA. Patch systems to mitigate BlueKeep.",
        "Real-World Example":"BlueKeep attacks on unpatched RDP servers.",
        "Common Services":"Remote Desktop Protocol (RDP).",
        "Misconfigurations":"Enabling RDP on all interfaces. Allowing open access to port 3389.",
        "Security Features":"Firewalls, Network Level Authentication (NLA)."
    },
    5432: {
        "Use": "PostgreSQL database services.",
        "Vulnerabilities": "Weak passwords. Misconfigurations.",
        "Attack Methods": "Credential brute-forcing. Exploiting unpatched vulnerabilities.",
        "Prevention": "Use strong passwords. Limit access with firewalls.",
        "Real-World Example":"PostgreSQL database breaches due to weak passwords. Data breaches due to exposed PostgreSQL servers.",
        "Common Services":"PostgreSQL.",
        "Misconfigurations":"Enabling PostgreSQL to listen on all interfaces. Dafault configurations exposing the database publicaly.",
        "Security Features":"Firewalls, Authentication, Encryption, Regular backups, Role-based access control (RBAC)."
    },
    5900: {
        "Use": "Remote desktop via VNC.",
        "Vulnerabilities": "Weak authentication. Exploitable software vulnerabilities.",
        "Attack Methods": "Brute-forcing credentials. Exploiting outdated VNC servers.",
        "Prevention": "Use strong passwords. Keep VNC software updated.",
        "Real-World Example":"VNC server vulnerabilities exploited by attackers.",
        "Common Services":"VNC.",
        "Misconfigurations":"Enabling VNC on all interfaces. Allowing open access to port 5900.",
        "Security Features":"Firewalls, Authentication, Encryption, Regular backups, Patch management."
    },
    8080: {
        "Use": "Alternative HTTP port.",
        "Vulnerabilities": "Injection vulnerabilities. MITM attacks.",
        "Attack Methods": "Eavesdropping. Exploiting web app vulnerabilities.",
        "Prevention": "Use HTTPS. Regularly scan for vulnerabilities.",
        "Real-World Example":"Web app vulnerabilities exploited by attackers, Exposed Jenkins servers attacked via port 8080.",
        "Common Services":"Apache Tomcat, Jenkins.",
        "Misconfigurations":"Exposing Jenkins servers on port 8080. Weak or no authentication on admin interfaces.",
        "Security Features":"HTTPS for secure admin sessions."
        
    },
    8443: {
        "Use": "Alternative HTTPS port.",
        "Vulnerabilities": "Weak SSL/TLS configurations.",
        "Attack Methods": "Exploiting deprecated protocols.",
        "Prevention": "Use strong SSL/TLS configurations.",
        "Real-World Example":"Weak SSL/TLS configurations exploited by attackers.",
        "Common Services":"Apache Tomcat.",
        "Misconfigurations":"Weak or no SSL/TLS configurations.",
        "Security Features":"Strong SSL/TLS configurations, Regularly update and patch software."
    },
}
