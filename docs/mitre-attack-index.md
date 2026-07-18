# MITRE ATT&CK Mapping Index

A single consolidated view of every technique ID referenced across this repo's 11 playbooks, organized by ATT&CK tactic. Each playbook's own header states its specific technique IDs — this file is the cross-repo index for quickly finding which playbook covers a given technique or tactic.

## Initial Access

| Technique | ID | Playbook |
|---|---|---|
| Phishing | T1566 | Phishing & Initial Access |
| Spearphishing Attachment | T1566.001 | Phishing & Initial Access |
| Spearphishing Link | T1566.002 | Phishing & Initial Access |
| Valid Accounts (Cloud) | T1078.004 | Cloud Misconfiguration Exposure |

## Execution

| Technique | ID | Playbook |
|---|---|---|
| User Execution | T1204 | Phishing & Initial Access |
| PowerShell | T1059.001 | PowerShell & LOLBin Execution |
| System Binary Proxy Execution | T1218 | PowerShell & LOLBin Execution |

## Persistence / Impact (Recovery Inhibition)

| Technique | ID | Playbook |
|---|---|---|
| Inhibit System Recovery | T1490 | Ransomware Detection & Response |
| Service Stop | T1489 | Ransomware Detection & Response |

## Credential Access

| Technique | ID | Playbook |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Dumping via LSASS Access |
| Brute Force | T1110 | Brute Force & Credential Stuffing |
| Password Spraying | T1110.003 | Brute Force & Credential Stuffing |
| Credential Stuffing | T1110.004 | Brute Force & Credential Stuffing |

## Discovery

| Technique | ID | Playbook |
|---|---|---|
| System Information Discovery | T1082 | Post-Access Reconnaissance & Discovery |
| Account Discovery | T1087 | Post-Access Reconnaissance & Discovery |
| Remote System Discovery | T1018 | Post-Access Reconnaissance & Discovery |
| System Network Configuration Discovery | T1016 | Post-Access Reconnaissance & Discovery |
| Permission Groups Discovery | T1069 | Post-Access Reconnaissance & Discovery |
| Cloud Infrastructure Discovery | T1580 | Cloud Misconfiguration Exposure |

## Lateral Movement

| Technique | ID | Playbook |
|---|---|---|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement via PsExec/WMI |
| Windows Management Instrumentation | T1047 | Lateral Movement via PsExec/WMI |
| Service Execution | T1569.002 | Lateral Movement via PsExec/WMI |

## Command and Control

| Technique | ID | Playbook |
|---|---|---|
| Application Layer Protocol | T1071 | C2 Beaconing Detection |
| Encrypted Channel | T1573 | C2 Beaconing Detection |
| Dynamic Resolution | T1568 | C2 Beaconing Detection |

## Exfiltration

| Technique | ID | Playbook |
|---|---|---|
| Exfiltration Over C2 Channel | T1041 | Data Exfiltration |
| Exfiltration Over Web Service | T1567 | Data Exfiltration / Insider Threat |
| Exfiltration Over Alternative Protocol | T1048 | Data Exfiltration |

## Impact

| Technique | ID | Playbook |
|---|---|---|
| Data Encrypted for Impact | T1486 | Ransomware Detection & Response |

## Collection / Insider-specific

| Technique | ID | Playbook |
|---|---|---|
| Data from Cloud Storage | T1530 | Insider Threat / Cloud Misconfiguration Exposure |
| Data from Information Repositories | T1213 | Insider Threat |
| Data Staged | T1074 | Insider Threat |

---

## How to use this index

If you're given a technique ID or tactic name (in an interview, a real alert, or a CTI report) and want to know which playbook in this repo covers it, search this file first — it's faster than opening each playbook individually. If a technique isn't listed here, it's not yet covered by this framework and is a candidate for a future playbook addition.
