# Glossary

Terms used across this repo's playbooks, defined once here for quick reference.

**AMSI (Antimalware Scan Interface)** — Windows API allowing security products to inspect script content (PowerShell, VBScript) before execution, including obfuscated scripts. A common attacker target for bypass techniques.

**Beacon / Beaconing** — Regular, periodic outbound communication from a compromised host to attacker-controlled infrastructure, used to receive commands or exfiltrate data in small increments. Detected primarily through interval regularity analysis.

**BIOC (Behavioral Indicator of Compromise)** — Cortex XDR's term for a custom detection rule based on behavior patterns rather than a static indicator (hash, IP).

**CASB (Cloud Access Security Broker)** — A tool/service that sits between users and cloud applications, providing visibility and policy enforcement over cloud service usage, including distinguishing sanctioned corporate-tenant use from personal-account use of the same service.

**CSPM (Cloud Security Posture Management)** — Tooling that continuously assesses cloud infrastructure configuration against security best practices, flagging misconfigurations like public storage buckets or overly permissive IAM policies.

**DGA (Domain Generation Algorithm)** — A technique malware uses to generate large numbers of algorithmically-produced domain names for C2 infrastructure, making domain-based blocking harder since the specific domains change frequently.

**DLP (Data Loss Prevention)** — Tooling that inspects data in motion or at rest for sensitive content (PII, classified documents, source code) and can alert on or block unauthorized movement.

**Golden Ticket / Silver Ticket** — Kerberos ticket forgery attacks using a compromised KRBTGT account hash (golden) or a compromised service account hash (silver) to impersonate any user within a domain (golden) or a specific service (silver).

**IAM (Identity and Access Management)** — The framework of policies and technologies governing who can access what within an organization's systems, especially in cloud environments (AWS IAM, Azure RBAC, GCP IAM).

**IOC (Indicator of Compromise)** — A specific, static artifact (file hash, IP address, domain) associated with known malicious activity. Contrasted with behavioral detection, which looks at patterns rather than static artifacts.

**JA3 / JA3S** — Fingerprinting techniques for TLS client (JA3) and server (JA3S) handshake behavior, useful for identifying known malware/C2 framework traffic even when fully encrypted.

**Kerberoasting** — Requesting Kerberos service tickets for accounts with Service Principal Names set, then attempting offline password cracking against the ticket's encrypted portion.

**LOLBin (Living-Off-the-Land Binary)** — A legitimate, often Microsoft-signed system binary repurposed by an attacker for malicious ends (e.g., `certutil.exe` used to download or decode files, `mshta.exe` used to execute scripts).

**LSASS (Local Security Authority Subsystem Service)** — The Windows process responsible for enforcing security policy and storing credentials in memory, making it a primary target for credential-dumping techniques.

**MITRE ATT&CK** — A publicly maintained knowledge base of adversary tactics and techniques, used throughout this repo to categorize each playbook's technique with a standard reference ID.

**Password Spraying** — A brute-force variant using a small number of password attempts across many accounts (rather than many attempts against one account), specifically designed to stay under per-account lockout thresholds.

**Sysmon (System Monitor)** — A Sysinternals tool providing detailed Windows process, network, and file-system event logging beyond native Windows auditing, foundational to most host-based playbooks in this repo.

**UEBA (User and Entity Behavior Analytics)** — Analysis that establishes a behavioral baseline for users/systems and flags deviations from that baseline, foundational to insider threat detection specifically since there's no malicious binary or unauthorized login to anchor on.

**Zeek (formerly Bro)** — A passive network traffic analysis framework producing structured logs (`conn.log`, `dns.log`, `ssl.log`) used throughout the C2 beaconing and data exfiltration playbooks.
