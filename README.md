# Enterprise XDR Investigation Framework

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

## How to use this

1. Pick a technique from `detections/playbooks/`.
2. Read it top to bottom — it's written as "alert fires → here's what you check, in order, and why."
3. Reproduce the telemetry yourself where possible (Sysmon config + a lab VM, or sample logs).
4. Map it to MITRE ATT&CK in `docs/`.
5. Repeat until the *pattern* — not the vendor UI — is what you see when you close your eyes.

## First playbook

See [`detections/playbooks/lateral-movement-psexec-wmi.md`](detections/playbooks/lateral-movement-psexec-wmi.md) — lateral movement via PsExec/WMI, the single most common real-world SOC escalation. Use it as the template for every other technique you add.

## Status

🚧 Living document — built while onboarding into a SOC analyst role. Playbooks are added as I work through techniques, not all at once.
