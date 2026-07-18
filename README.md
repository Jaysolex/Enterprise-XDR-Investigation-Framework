# Tripwire: A SOC Analyst's Detection Handbook

**Reverse-engineering enterprise XDR investigation workflows using open security tooling.**

> This project does not simulate owning Cortex XDR, CrowdStrike Falcon, or any specific vendor product. It documents and reproduces the *investigation workflow* that sits behind all of them — detection → triage → validation → scope → containment → recovery → detection improvement — using open telemetry sources (Sysmon, auditd, Zeek, osquery) so the logic transfers to whatever console you're handed on day one.

## Why this exists

Most SOC analysts learn **where to click** in a specific vendor console. Very few can explain **why** they're clicking it — what telemetry triggered the alert, what the analyst is actually trying to disprove or confirm, and what "done" looks like at each stage. That gap is what separates a Tier 1 alert-closer from a senior analyst who can walk into any XDR platform and be productive in a week.

This repo is my personal handbook for closing that gap — built to be read like a field manual, not a course.

## Core model: the XDR investigation lifecycle

```
Endpoint
   │
   ▼
Telemetry Collection      (EDR sensor / Sysmon / auditd / osquery)
   │
   ▼
Detection                 (behavioral rule, ML model, IOC match, correlation)
   │
   ▼
Triage                    (is this worth an analyst's time right now?)
   │
   ▼
Investigation             (process tree, command line, parent/child, network)
   │
   ▼
Threat Validation         (true positive vs. benign / false positive)
   │
   ▼
Scope                     (what else is affected — hosts, identities, data)
   │
   ▼
Containment               (isolate host, disable account, block hash/IP)
   │
   ▼
Recovery                  (restore, re-image, credential rotation)
   │
   ▼
Detection Improvement     (write/tune the rule so this is caught faster next time)
```

Every vendor's console is a different skin on this same loop. Cortex XDR calls the triage view "Incident Manager," CrowdStrike calls it the "Incident Workbench," Defender calls it the "Incident" blade — same nine boxes above.

## Repository structure

```
Enterprise-XDR-Investigation-Framework/
├── README.md
├── architecture/
│   ├── windows/          # ETW, Sysmon event IDs, AMSI, WMI, process trees
│   ├── linux/            # auditd, eBPF, syscall telemetry
│   ├── identity/         # Kerberos/NTLM abuse, Entra ID sign-in logs, Okta
│   └── network/          # Zeek/Suricata telemetry, C2 beaconing patterns
├── detections/
│   ├── timelines/        # Reconstructed attack timelines from sample data
│   └── playbooks/        # ⭐ one workflow per attack technique (start here)
├── runbooks/
│   ├── process-trees/    # Annotated real/synthetic process tree examples
│   ├── command-lines/    # Suspicious command-line pattern library
│   └── telemetry/        # Field-by-field breakdown of key log sources
├── containment/           # Isolation, credential reset, and blocking procedures
├── reports/                # Post-incident report templates
└── docs/                   # Glossary, MITRE ATT&CK mapping index
```


## Playbooks

Eight playbooks are complete, forming one continuous attack lifecycle from initial access through impact — each links forward/backward to the stages around it rather than standing alone.

| # | Playbook | MITRE ATT&CK | Chain position |
|---|---|---|---|
| 1 | [Phishing & Initial Access](detections/playbooks/phishing-initial-access.md) | T1566, T1204 | Entry point |
| 2 | [Post-Access Reconnaissance & Discovery](detections/playbooks/recon-discovery.md) | T1082, T1087, T1018 | Orientation |
| 3 | [Credential Dumping via LSASS Access](detections/playbooks/credential-dumping-lsass.md) | T1003.001 | Post-access |
| 4 | [Lateral Movement via PsExec/WMI](detections/playbooks/lateral-movement-psexec-wmi.md) | T1021.002, T1047 | Propagation |
| 5 | [Suspicious PowerShell & LOLBin Execution](detections/playbooks/powershell-lolbins.md) | T1059.001, T1218 | Staging/execution |
| 6 | [C2 Beaconing Detection](detections/playbooks/c2-beaconing.md) | T1071, T1573 | Command channel |
| 7 | [Data Exfiltration](detections/playbooks/data-exfiltration.md) | T1041, T1567 | Objective/impact |
| 8 | [Ransomware Detection & Response](detections/playbooks/ransomware-detection-response.md) | T1486, T1490 | Alternate impact path |

The chain reads: a user opens something they shouldn't (1) → the attacker orients themselves in the environment, figuring out what's worth targeting (2) → dumps credentials from the host (3) → moves to other machines using those credentials (4) → stages further tooling using living-off-the-land techniques (5) → maintains a command channel back to their infrastructure (6) → and either exfiltrates data (7) or, in the more destructive case, encrypts everything reachable (8). Ransomware can also enter the chain directly from stage 4, without necessarily involving C2 or exfiltration first.

Every playbook follows the same fixed shape: detection signals → telemetry sources → triage questions → investigation/process tree → validation criteria → scope → containment → recovery → detection improvement → multi-platform query reference (Cortex XDR, Defender XDR, CrowdStrike, Splunk, Elastic) → escalation/handoff notes. Use playbook #3 (lateral movement) as the reference shape if adding a new one.

## How to use this

1. Read the playbooks in chain order (table above) once, top to bottom, to see the full narrative — then treat each one as a standalone reference afterward.
2. Reproduce the telemetry yourself where possible (Sysmon config + a lab VM, or sample logs).
3. Map each to MITRE ATT&CK — already listed per playbook above; expand in `docs/` as needed.
4. Repeat until the *pattern* — not the vendor UI — is what you see when you close your eyes.

## Status

🚧 Living document — built while onboarding into a SOC analyst role. Core attack-chain playbooks (8) are complete. Next additions: insider threat, brute force/credential stuffing, cloud misconfiguration exposure.
