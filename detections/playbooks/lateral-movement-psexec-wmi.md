# Playbook: Lateral Movement via PsExec / WMI

**MITRE ATT&CK:** T1021.002 (SMB/Windows Admin Shares), T1047 (WMI), T1569.002 (Service Execution)

**Why this one first:** it's the highest-frequency escalation in a real SOC queue. Attackers (and pentesters) use PsExec/WMI to move host-to-host because it uses legitimate admin tooling — which is exactly why it's hard to triage and a great test of whether you understand telemetry vs. just reading an alert title.

---

## 1. What the detection actually looks like

An XDR platform doesn't detect "PsExec." It detects a **combination** of signals that PsExec/WMI activity produces:

- A new service is created remotely (`PSEXESVC` service name is the classic tell, but attackers rename the binary)
- `services.exe` spawns an unusual child process
- `WmiPrvSE.exe` (WMI Provider Host) spawns `cmd.exe` or `powershell.exe`
- A remote SMB session authenticates and writes a binary/service to `ADMIN$` or `C$`
- Sequential logons of the same account across multiple hosts in a short window

If you only know "Cortex flagged lateral movement," you can't investigate. You need to know **which** of these fired.

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Sysmon Event ID 1 | Process creation — parent/child, command line, hashes |
| Sysmon Event ID 3 | Network connection — confirms SMB (445) or WMI (135) traffic |
| Windows Security Event 4688 | Process creation (native, no Sysmon needed) |
| Windows Security Event 7045 | New service installed — **the PsExec smoking gun** |
| Windows Security Event 4624/4625 | Logon success/failure, logon type 3 (network) |
| WMI-Activity/Operational log | WMI method execution (`ExecMethod`), catches WMI-based lateral movement Sysmon can miss |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is the account a known admin who does this routinely (patch deployment, SCCM)?** Check against a change calendar / known-good service accounts first. This alone closes a huge fraction of these as benign.
2. **Is the source host one that normally pushes software (jump box, SCCM server, RMM tool)?** If yes and the account matches, likely benign — but still confirm the binary hash.
3. **Does the destination service binary path look normal** (`C:\Windows\...`) **or does it look staged** (`C:\Users\Public\`, `C:\ProgramData\`, a random temp path)? Staged paths escalate immediately.
4. **Is the service name random/gibberish** rather than a recognizable product name? Escalate.

If any answer in steps 3–4 is "suspicious," move to full investigation — don't spend more time triaging.

## 4. Investigation: building the process tree

You're trying to answer: *what process created the service, what did the service execute, and what did that process do next?*

Typical malicious tree:
```
wmiprvse.exe (or services.exe)
  └── cmd.exe /c "whoami && net user"          ← recon after landing
        └── powershell.exe -enc <base64>       ← next-stage payload
```

Command-line details that matter:
- `-enc` / `-EncodedCommand` on PowerShell → always pull and decode the base64 payload before deciding anything
- `net use \\host\C$` immediately before service creation → confirms manual SMB staging
- Service binary path containing `\\127.0.0.1\ADMIN$` or written just seconds before execution → classic PsExec sequence (copy binary → create service → start service → delete service)

## 5. Threat validation

Confirm true positive if **two or more** of the following are true:
- Service binary hash has zero or low reputation on threat intel (VirusTotal, internal allowlist mismatch)
- Command line contains encoded/obfuscated PowerShell, `certutil -decode`, or `-nop -w hidden`
- Source host has other suspicious activity in the same time window (e.g., credential dumping, prior alert)
- The account used doesn't normally log onto the destination host (check historical logon baseline)

False positive indicators:
- Binary matches a known RMM/patch tool signed by a recognized vendor
- Account and source host match a documented change ticket

## 6. Scope

Once validated, immediately check:
- **Same account, other hosts:** search Event 4624 (logon type 3) for the same account across the environment in the same time window — lateral movement is rarely one hop.
- **Same source host, other destinations:** did this host touch other machines' ADMIN$ shares?
- **Credential reuse:** was this a local admin password reused across many hosts (classic "pass the hash" enabler)? Check if the account is a shared local admin vs. a domain account.

## 7. Containment

Priority order:
1. Network-isolate the destination host(s) via the EDR agent (not a full shutdown — you want to preserve memory/forensic state).
2. Disable the compromised account (don't delete — you'll need it for investigation).
3. If local admin credentials were reused, flag for org-wide rotation (this is usually a bigger finding than the single incident).
4. Block the malicious service binary hash at the EDR/AV layer across the fleet.

## 8. Recovery

- Re-image hosts where a second-stage payload executed (don't just "clean" — if `powershell -enc` ran, assume further tooling was staged).
- Rotate credentials for the compromised account and any local admin accounts shared across the affected hosts.
- Confirm the malicious service was removed (attackers sometimes leave it disabled rather than deleted).

## 9. Detection improvement

After closing the incident, ask: **would we have caught this faster?**
- If Event 7045 (new service) isn't currently alerting on non-standard install paths, that's a detection gap — write it up.
- If the environment has no baseline of "which accounts normally do remote admin," that's a detection engineering opportunity (UEBA-style anomaly rule).

## 10. Talking points for interviews

If asked "walk me through how you'd investigate a lateral movement alert":
1. State what telemetry generated it (don't just say "the XDR flagged it").
2. Describe the triage questions you'd ask before touching the console.
3. Walk the process tree and explain what each hop tells you.
4. Give a clear true/false positive criterion — interviewers want to hear you have a *repeatable standard*, not a gut feeling.
5. Close with scope → containment → the detection-improvement loop. This last part is what separates senior candidates — most people stop at "I'd isolate the host."
