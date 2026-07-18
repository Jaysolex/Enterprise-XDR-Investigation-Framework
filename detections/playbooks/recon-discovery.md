# Playbook: Post-Access Reconnaissance & Discovery

**MITRE ATT&CK:** T1082 (System Information Discovery), T1087 (Account Discovery), T1018 (Remote System Discovery), T1016 (System Network Configuration Discovery), T1069 (Permission Groups Discovery)

**Where this sits in the chain:** this is the step most chains skip over when explaining an incident, and it's usually the first thing an attacker actually does after landing — before they know what's worth stealing or where to move next, they need to know what they're standing in. This playbook sits between initial access (phishing) and credential dumping: the recon commands here are often what tells the attacker *which* credentials are worth going after and *which* hosts are worth moving to.

---

## 1. What the detection actually looks like

Recon rarely trips a single high-confidence alert on its own — most of the individual commands are completely legitimate admin tools. What makes it detectable is **sequence and speed**:

- A burst of discovery commands (`whoami`, `net user`, `net group`, `ipconfig /all`, `nltest`, `systeminfo`) run in quick succession from the same session — legitimate admins rarely chain all of these together in seconds
- These commands running from a process that isn't a normal interactive admin session — e.g., spawned from a script, a phishing payload's child process, or a process already flagged for suspicious activity elsewhere in the chain
- Discovery commands run by an account that doesn't normally perform this kind of administrative enumeration
- `nltest /domain_trusts` or `net group "Domain Admins" /domain` specifically — these go beyond basic host info and start mapping the broader Active Directory environment, a stronger signal than local host enumeration alone

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Sysmon Event ID 1 | Process creation — command line for every discovery command executed |
| Windows Security Event 4688 | Native process creation logging, useful if Sysmon isn't deployed everywhere |
| PowerShell Event ID 4104 | Script block logging — catches discovery done via `Get-ADUser`, `Get-NetLocalGroup`, or similar PowerShell cmdlets rather than native binaries |
| EDR process-chain telemetry | Ties the discovery commands back to the parent process (phishing payload, LOLBin, or interactive shell) |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is this a known admin performing a documented task** (asset inventory, account audit, a scheduled compliance script)? Check against your change calendar and known admin accounts first — a large share of "recon" alerts are legitimate IT/security operations work.
2. **How many discovery commands ran, and how fast?** One or two commands over several minutes during an interactive session looks like a human doing normal troubleshooting. Ten-plus commands in under a minute looks scripted.
3. **What's the parent process?** Discovery commands spawned from `cmd.exe`/`powershell.exe` that were themselves spawned from an Office application or a LOLBin chain elsewhere in this incident should be treated as part of the same incident, not assessed alone.
4. **Did the enumeration go beyond the local host** — domain trust queries, remote system discovery, Active Directory group enumeration? This is the point where "someone is curious about their own machine" stops being a plausible explanation.

If the commands are scripted/fast, tied to a parent process already implicated elsewhere in the incident, or extend beyond local host information into domain-level enumeration, escalate to full investigation.

## 4. Investigation: reading the recon sequence

You're answering: *what did the attacker learn, and what does it tell you about where they're likely to go next.*

Typical sequence and what each step is actually for:
```
whoami /all                       ← confirm current privilege level and group memberships
net user                          ← enumerate local accounts
net user /domain                  ← enumerate domain accounts (if domain-joined)
net group "Domain Admins" /domain ← identify high-value targets
ipconfig /all                     ← map the local network, identify domain controllers via DNS suffix
nltest /domain_trusts             ← map trust relationships between domains, useful for planning lateral movement
systeminfo                        ← OS version, patch level, useful for identifying viable exploits or living-off-the-land options
net view \\<hostname>              ← enumerate shares on a specific target, often the step just before lateral movement begins
```

Reading this as a sequence tells a story: an attacker who runs the first four is doing basic orientation; one who progresses into domain trust and remote system discovery is actively planning their next move, and you should expect lateral movement or further credential access to follow shortly, not investigate this in isolation and move on.

## 5. Threat validation

Confirm true positive if **two or more** of the following are true:
- Multiple discovery commands executed in rapid succession (scripted timing, not human-paced)
- Parent process is a phishing payload, LOLBin, or a process already flagged elsewhere in this incident
- Enumeration extends beyond the local host into domain/AD-level discovery
- Account performing the enumeration has no documented reason to do so

False positive indicators:
- Commands match a known, scheduled inventory/compliance script and the account is expected to run it
- Slow, human-paced execution consistent with a help desk technician troubleshooting a single reported issue

## 6. Scope

Once validated:
- **Check what the attacker actually learned** — specifically, did the enumeration surface a privileged account, a domain controller, or a high-value share? This tells you what to watch for next, before it happens rather than after.
- **Correlate forward** — recon is a leading indicator, not a standalone incident; actively look for credential access or lateral movement attempts against whatever the recon surfaced, in the hours immediately following.
- **Check for the same command sequence on other hosts** if this appears scripted — a repeatable recon script run once is often run against multiple hosts as part of the same operation.

## 7. Containment

Priority order:
1. If recon is confirmed and tied to an already-compromised process/session, contain at the level appropriate to that upstream compromise (isolate the host, disable the account) — recon alone rarely needs a distinct containment action beyond what the parent incident already requires.
2. If the recon specifically surfaced high-value accounts or systems (Domain Admins group, a domain controller), proactively monitor or pre-emptively harden those specific targets — this is one of the few playbooks where containment can mean "watch this thing more closely" rather than "isolate it," since the recon itself tells you where to look next.

## 8. Recovery

- Recovery here typically follows whatever upstream compromise the recon was part of — this playbook rarely has independent recovery steps, since discovery alone doesn't change system state.
- If domain-level information was gathered (trust relationships, privileged group membership), consider this exposed knowledge even after the host is cleaned — the attacker retains what they learned even if access is revoked, which is a reason to accelerate broader hardening (privileged account monitoring, tighter group membership) rather than treat the incident as fully closed once the host is contained.

## 9. Detection improvement

- If there's no existing detection for command-sequence/velocity (multiple discovery commands in a short window from one session), that's a meaningful gap — individual commands are too noisy to alert on alone, but the sequence and speed pattern is a strong, learnable signal.
- Domain-trust and Domain Admins group enumeration specifically are worth a dedicated high-fidelity rule, since legitimate use of these specific commands is rare enough that alerting on them directly produces low noise.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter action_process_image_name in ("whoami.exe", "net.exe", "nltest.exe", "systeminfo.exe", "ipconfig.exe")
| comp count() as cmd_count by agent_hostname, actor_effective_username, causality_actor_process_image_name
| filter cmd_count >= 4
```

**Microsoft Defender XDR (KQL / Advanced Hunting)**
```kql
DeviceProcessEvents
| where FileName in~ ("whoami.exe", "net.exe", "nltest.exe", "systeminfo.exe", "ipconfig.exe")
| summarize CmdCount = count(), Commands = make_set(ProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 5m)
| where CmdCount >= 4
```
Domain trust / Domain Admins enumeration specifically:
```kql
DeviceProcessEvents
| where ProcessCommandLine has "domain_trusts" or ProcessCommandLine has "Domain Admins"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

**CrowdStrike Falcon (Event Search / Falcon Query Language)**
```
event_simpleName=ProcessRollup2
| FileName IN (whoami.exe, net.exe, nltest.exe, systeminfo.exe, ipconfig.exe)
| stats count as cmd_count by ComputerName, UserName
| where cmd_count >= 4
```

**Splunk**
```spl
index=main EventCode=1 (Image="*whoami.exe" OR Image="*net.exe" OR Image="*nltest.exe" OR Image="*systeminfo.exe")
| bucket _time span=5m
| stats count as cmd_count values(CommandLine) as commands by _time, ComputerName, User
| where cmd_count >= 4
```

**Elastic (EQL sequence query)**
```eql
sequence by process.parent.entity_id with maxspan=1m
  [process where process.name in ("whoami.exe", "net.exe")]
  [process where process.name in ("nltest.exe", "systeminfo.exe")]
```

## 11. Escalation and handoff notes

When writing this up for the incident ticket:
1. List the full command sequence in the order observed, not just "recon commands detected" — the sequence itself is diagnostic of intent (local orientation vs. domain-level planning).
2. Explicitly state what the attacker likely learned (privileged accounts identified, domain controllers located) so downstream monitoring can watch those specific targets.
3. Reference the parent process/incident this recon is tied to — this playbook almost never stands alone, and a ticket that treats it as isolated undersells its significance.
4. If domain-level information was gathered, flag this for follow-up even after the immediate host is contained — the knowledge gained doesn't go away when the host is cleaned.
