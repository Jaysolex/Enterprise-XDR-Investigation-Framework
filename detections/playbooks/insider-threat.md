# Playbook: Insider Threat Detection

**MITRE ATT&CK:** T1530 (Data from Cloud Storage), T1213 (Data from Information Repositories), T1074 (Data Staged), T1567 (Exfiltration Over Web Service — insider variant)

**Where this sits in the framework:** every other playbook in this repo assumes an external attacker gaining access. This one assumes the access was never illegitimate to begin with — the account, the permissions, and the login are all exactly what they should be. That single difference changes almost everything about how you triage and validate, and it's worth treating as a genuinely separate skill rather than a variant of the exfiltration playbook.

---

## 1. What the detection actually looks like

Insider threat detection is built almost entirely on **baseline deviation**, because there's no malicious binary or unauthorized login to anchor on:

- Access to files/systems/repositories outside an employee's normal job function or historical access pattern
- A sudden spike in document access volume, especially shortly before a resignation, termination, or role change (HR-triggered context matters enormously here)
- After-hours access inconsistent with the employee's normal working pattern
- Mass download or printing of sensitive documents
- Use of personal cloud storage, USB devices, or personal email from a corporate endpoint to move data
- Access to systems/data the employee has legitimate permission to reach, but no business reason to be looking at (e.g., an employee outside HR accessing compensation records)

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| DLP (Data Loss Prevention) alerts | Content-based matches on sensitive data movement — the most direct signal available |
| File/document access audit logs (SharePoint, file servers, Google Drive) | Who accessed what, when, and how much |
| USB/removable media logs | Device insertion events and file copy operations to external storage |
| Print logs | Volume and content-type of printed material, if enabled |
| HR/IT offboarding calendar | Context that changes everything — an employee's last two weeks of employment reads very differently than a random Tuesday |
| CASB (Cloud Access Security Broker) logs | Personal cloud storage or personal email use from managed devices |

## 3. Triage: is this worth escalating?

Ask, in order, and note this playbook's triage sequence is different from every other in this repo — **context and HR timing come before technical signal**, not after:

1. **Is this employee in a resignation, termination, or performance-management window?** Check with HR/legal before doing anything else technical — this single fact reframes every subsequent question, and most insider programs require HR/legal involvement from the very start, not after validation.
2. **Is the access within the employee's job function, just unusual in volume or timing?** A salesperson accessing the CRM heavily before quitting to join a competitor is a different (and very common) scenario from someone accessing systems entirely outside their role.
3. **Was data actually moved off corporate infrastructure**, or just accessed/viewed? Viewing sensitive data the employee already has legitimate access to is a much lower-urgency finding than confirmed transfer to personal storage.
4. **Is there a stated business reason** you can verify — a manager-approved project, a legitimate role change — before treating this as suspicious?

Given the legal, HR, and employment-law sensitivity here, this playbook is triaged jointly with HR/legal far earlier than any other playbook in this repository — technical findings alone should not drive action without that involvement.

## 4. Investigation: building the access and movement timeline

You're answering: *what did this person access, over what timeframe, and did any of it leave the organization's control.*

Typical timeline to build:
```
Access spike begins (often correlates with resignation/notice period start)
  └── Broad document access across repositories outside normal scope
        └── Files copied to USB or uploaded to personal cloud storage
              └── (sometimes) mass download shortly before last working day
```

Details that matter:
- **Volume relative to the individual's own baseline**, not a generic organizational average — a data scientist normally pulling large datasets looks completely different from a person in an unrelated role suddenly doing the same
- **Destination of any data movement**: personal email, personal cloud storage account (not the corporate tenant), or a USB device are the highest-concern destinations; a corporate-sanctioned collaboration tool is lower concern even at high volume
- **Timing relative to HR events**: two weeks before a resignation date is a materially different finding than the same access pattern six months into stable employment

## 5. Threat validation

This playbook doesn't use a clean "true/false positive" framing the way technical playbooks do — the finding is rarely binary. Instead, categorize as:

- **Requires immediate action**: confirmed transfer of sensitive data to personal infrastructure, especially inside a resignation/termination window
- **Requires HR/manager follow-up, not security containment**: unusual access explainable by a legitimate but undocumented business reason (still worth closing the documentation gap, but not a security incident)
- **Monitor, no action yet**: access pattern deviates from baseline but no data movement confirmed and no HR context suggests urgency

## 6. Scope

Once elevated to "requires action":
- **Identify everything the individual had access to**, not just what they're confirmed to have taken — insider cases often expand in scope once the full access footprint is reviewed.
- **Check for coordination** — did this individual's access pattern correlate with another employee's, suggesting more than one person involved (rare, but changes the entire response).
- **Check personal device/BYOD policies** for what jurisdiction you have over data once it reaches personal infrastructure — this affects what recovery options are realistically available and is a legal question, not a technical one.

## 7. Containment

Priority order, and note this is one of the few playbooks where **legal/HR often leads the containment decision, not security**:
1. Coordinate with HR/legal on timing — in active employment situations, premature account restriction can tip off the individual before evidence is preserved, and in some jurisdictions there are specific legal requirements around employee monitoring and confrontation.
2. Preserve evidence (audit logs, DLP alerts, access records) before any account action is taken.
3. Restrict access at the point HR/legal determines appropriate — often coordinated with an exit interview or termination meeting rather than done unilaterally by security first.
4. Revoke access to corporate systems and any active sessions once the coordinated action point is reached.

## 8. Recovery

- Recovery here is largely a legal/HR process (potential legal action, policy enforcement) rather than a technical remediation — security's role is usually evidence preservation and access termination, not "fixing" anything technical.
- Review whether the access that enabled this was appropriately scoped in the first place — insider cases frequently reveal overly broad permissions that should be tightened regardless of this specific incident's outcome.

## 9. Detection improvement

- If user behavior analytics (UEBA) baselining isn't in place, that's the foundational gap for this entire category — without a baseline, "unusual" has no reference point.
- Review whether offboarding/resignation-window monitoring is automated (a security team flag triggered by HR's process) rather than relying on security discovering the HR context independently after the fact — this integration is one of the highest-value, lowest-cost detection improvements available for this category specifically.

## 10. XDR/EDR query reference

Insider threat detection leans more heavily on DLP/CASB/UEBA platforms than traditional EDR telemetry, but the overlap points are still useful:

**Microsoft Defender XDR / Microsoft Purview (KQL)**
```kql
CloudAppEvents
| where ActionType in ("FileDownloaded", "FileCopied") 
| where AccountDisplayName == "<employee>"
| summarize TotalFiles = count() by AccountDisplayName, bin(Timestamp, 1d)
| where TotalFiles > 100  // adjust threshold to individual baseline
```
USB/removable media activity:
```kql
DeviceEvents
| where ActionType == "UsbDriveMounted" or ActionType == "PnpDeviceConnected"
| where DeviceName == "<employee_device>"
```

**Splunk (with DLP/CASB data ingested)**
```spl
index=dlp user="<employee>"
| stats count as event_count sum(file_size) as total_bytes by user, _time
| where event_count > 100
```

**Cortex XDR (XQL)** — useful for the endpoint-side USB/file-movement angle
```
dataset = xdr_data
| filter event_type = ENUM.FILE
| filter actor_effective_username = "<employee>"
| filter action_file_path contains "USB" or action_file_path contains "removable"
```

## 11. Escalation and handoff notes

When writing this up:
1. This ticket is written jointly with HR/legal, not solely by security — document who was consulted and when, since this record matters for any subsequent legal action.
2. State the access pattern relative to the individual's own baseline explicitly, not just raw volume numbers — raw numbers without a baseline comparison are not meaningful on their own in this category.
3. Note HR/employment context explicitly and the date it was confirmed (resignation date, notice period, performance status) — this is the single fact that most changes how this finding should be read.
4. Any containment action taken should note who authorized it and when — unlike every other playbook here, security acting unilaterally in this category can create legal exposure of its own.
