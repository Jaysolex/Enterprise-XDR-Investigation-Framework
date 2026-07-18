# Playbook: Ransomware Detection & Response

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1489 (Service Stop)

**Where this sits in the chain:** ransomware is often the visible, final act of an incident that already ran through several earlier stages — credential access, lateral movement, and sometimes exfiltration (double-extortion groups steal data before encrypting, specifically to have leverage even if backups restore cleanly). By the time encryption is visible, the response clock is different from every other playbook in this repo: this one is measured in minutes, not hours, because every minute of delay is more encrypted hosts.

---

## 1. What the detection actually looks like

- Mass file modification events across many files in a short window — the clearest and fastest signal available, since ransomware needs to touch a huge number of files quickly
- Shadow copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`) — nearly universal across ransomware families, since deleting recovery points is standard practice before or during encryption
- Backup-related services being stopped (`vssvc`, backup agent services) shortly before mass encryption begins
- Ransom note files appearing in multiple directories simultaneously (`README.txt`, `DECRYPT_INSTRUCTIONS.html`, or family-specific naming)
- A sudden spike in file rename/write operations across network shares from a single host, since ransomware frequently spreads by encrypting reachable shares in addition to the local disk

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Sysmon Event ID 11 | File creation — the ransom note appearing, and encrypted file writes if the extension changes |
| Sysmon Event ID 1 | Process creation — `vssadmin`, `wmic shadowcopy delete`, `bcdedit` (disabling recovery options) |
| File integrity monitoring / EDR file activity | Rate of file modification per second/minute — the single fastest confirmation signal available |
| Windows Security Event 7036/7040 | Service stop events, useful for catching backup agent/AV service termination |
| Network share access logs | Confirms whether encryption is spreading beyond the initial host via SMB |

## 3. Triage: is this worth escalating?

There is effectively no low-priority path in this playbook. Any confirmed mass file encryption or shadow copy deletion is escalated immediately, in parallel with (not after) initial triage questions. The triage questions here are about **scope and blast radius**, not "should we respond":

1. **Is this one host or many?** Check EDR/SIEM for the same file-modification-rate pattern across other hosts in the same time window — this determines whether you're isolating one machine or coordinating a much larger response.
2. **Are shares encrypted, not just the local host?** If yes, every host with access to that share is now a secondary concern even if not yet directly infected.
3. **Is backup infrastructure itself affected?** If backup servers or shadow copies show tampering, recovery options are actively narrowing in real time — this changes the urgency of isolating backup infrastructure specifically, immediately.

## 4. Investigation: confirming scope while containment is already underway

Unlike every other playbook in this repo, **containment starts in parallel with investigation, not after validation** — the cost of waiting for full confirmation before isolating a host is measured in additional encrypted machines.

Typical process sequence to look for:
```
<initial access/lateral movement process, from earlier playbooks>
  └── vssadmin.exe delete shadows /all /quiet          ← recovery point destruction
  └── net stop <backup service>                         ← disabling backup agents
  └── <ransomware binary> encrypting files at high rate  ← the encryption process itself
```

Details that matter:
- **Encryption rate**: file modification telemetry showing hundreds or thousands of writes per minute from a single process is close to unambiguous — almost nothing legitimate produces this pattern
- **File extension changes**: many ransomware families append a distinct extension (family-specific) to encrypted files — cataloging this extension quickly helps identify which ransomware family/strain you're dealing with, which matters for whether a public decryptor exists
- **Ransom note content**: don't spend time reading it for "understanding the attacker" — extract the contact/payment details only insofar as your incident response process requires them, and treat note content as evidence, not something to engage with directly

## 5. Threat validation

By the time you're running this playbook, validation has usually already happened implicitly — mass encryption in progress isn't something that needs a multi-factor confidence check the way a single suspicious login does. The validation question that still matters:

- **Confirm this is actual malicious encryption, not a legitimate encryption tool or scripted action** (rare, but a misconfigured backup/encryption job has been mistaken for ransomware before — check for a known scheduled task or admin action first if there's any ambiguity, but do this in parallel with containment, not before it)

## 6. Scope

This is the most urgent scoping exercise in the entire framework, because scope directly determines containment boundary:

- **Every host showing the same encryption/shadow-deletion pattern**, found via the same query run across the fleet, not host by host
- **Every network share reachable from affected hosts**, since ransomware frequently spreads laterally via SMB to any share the compromised account/host can reach
- **Backup infrastructure status** — confirm whether backups are intact, tampered, or also encrypted, since this single fact determines whether recovery is "restore from backup" or a much harder conversation
- **Whether data was exfiltrated before encryption** (double-extortion pattern) — check for the data-exfiltration playbook's indicators in the hours/days prior, since this changes the incident from "recovery problem" to "recovery problem plus a breach-notification problem"

## 7. Containment

This happens **immediately and in parallel with investigation**, not after it — this is the one playbook in the framework where that sequencing is different, and it matters that it's different for a real reason: encryption spreads faster than any other technique in this repo.

Priority order, executed as fast as possible:
1. Network-isolate every host showing encryption activity, immediately, using EDR-based isolation (not physically unplugging, which loses forensic state) — the moment you have a confirmed host, isolate it, don't wait to finish scoping everything first.
2. Disable or restrict the compromised account(s) across the domain, since ransomware operators frequently use a single compromised credential to reach multiple hosts/shares.
3. Isolate or restrict access to backup infrastructure specifically, even if not yet confirmed affected — protecting the ability to recover is as urgent as stopping further encryption.
4. Block any C2/exfiltration infrastructure identified from earlier stages of the same incident chain.

## 8. Recovery

- Recovery path depends entirely on backup integrity confirmed during scope — restoring from backups that are themselves compromised or encrypted just re-introduces the problem.
- Do not pay the ransom as a decision made at the analyst level — this is an organizational/legal/executive decision with implications far beyond technical recovery, and analysts should escalate the decision, not make it.
- Full re-image is standard for every confirmed-encrypted host — there is no partial-cleanup path for ransomware the way there might be for a contained credential dump.
- If data exfiltration is confirmed alongside encryption, recovery must run in parallel with breach-notification and legal processes, not sequentially after technical recovery completes.

## 9. Detection improvement

- If shadow copy deletion (`vssadmin delete shadows`) isn't already one of the highest-fidelity, fastest-alerting rules in your environment, that's the single most urgent detection gap to close after any ransomware incident — it's a near-universal precursor with very low false-positive risk.
- File-modification-rate anomaly detection (many EDR platforms have this natively) is worth confirming is actually tuned and enabled, since it's frequently the fastest available signal, faster than waiting for a ransom note to appear.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter action_process_image_command_line contains "vssadmin" and action_process_image_command_line contains "delete shadows"
| fields agent_hostname, actor_effective_username, action_process_image_command_line, _time
```

**Microsoft Defender XDR (KQL / Advanced Hunting)**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
File modification rate spike (requires DeviceFileEvents volume, aggregated):
```kql
DeviceFileEvents
| where ActionType == "FileModified"
| summarize FileWriteCount = count() by DeviceName, bin(Timestamp, 1m)
| where FileWriteCount > 100
```

**CrowdStrike Falcon (Event Search / Falcon Query Language)**
```
event_simpleName=ProcessRollup2 FileName=vssadmin.exe
| CommandLine="*delete*shadows*"
| table ComputerName, UserName, CommandLine, _time
```

**Splunk**
```spl
index=main EventCode=1 CommandLine="*vssadmin*delete*shadows*"
| table _time, ComputerName, User, CommandLine
```
File write rate spike:
```spl
index=main sourcetype=fileaudit
| bucket _time span=1m
| stats count as writes by _time, ComputerName
| where writes > 100
```

**Elastic (EQL)**
```eql
process where event.type == "start" and
  process.name == "vssadmin.exe" and
  process.command_line like "*delete*shadows*"
```

## 11. Escalation and handoff notes

When writing this up:
1. This is the one incident type where the ticket gets written *after* containment actions, not before — timestamp every containment action taken in real time as you take it, since reconstructing the timeline afterward from memory is unreliable under this kind of time pressure.
2. State backup integrity status explicitly and as early as possible in the ticket — this is the single fact leadership will ask for first.
3. Flag any confirmed or suspected data exfiltration prior to encryption immediately and separately from the technical recovery ticket, since it triggers a different (legal/compliance) workflow with its own urgency.
4. Reference every earlier stage of this incident chain (initial access, credential theft, lateral movement) found during scope — ransomware is very rarely the entire story, and the ticket should reflect the full lifecycle, not just the encryption event.
