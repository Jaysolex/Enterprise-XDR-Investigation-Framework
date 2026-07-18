# Windows Telemetry Reference

Background on the Windows-side data sources referenced throughout the playbooks in this repo — what each one actually captures and why it exists, separate from any single investigation.

## Sysmon (System Monitor)

Not part of Windows by default — a Sysinternals tool that must be installed and configured. Without it, you're relying on native Windows Security auditing alone, which is far less detailed for process/network telemetry.

Key event IDs used across this repo's playbooks:

| Event ID | Name | Used in |
|---|---|---|
| 1 | Process creation | Nearly every playbook — command line, parent/child relationship |
| 3 | Network connection | C2 beaconing, data exfiltration, lateral movement |
| 7 | Image/DLL loaded | AMSI bypass detection, LOLBin DLL loads |
| 10 | Process access | Credential dumping (LSASS access) |
| 11 | File creation | Ransomware (ransom notes, encrypted files), credential dumping (.dmp files), staging (archives) |

Sysmon's value over native logging is almost entirely in the **command line field** — native Windows Event 4688 can be configured to include command lines but doesn't by default, and Sysmon's process access/network events (10, 3) have no clean native equivalent at all.

## Native Windows Security Event Log

Doesn't require third-party tooling, but has real coverage gaps compared to Sysmon.

| Event ID | Name | Used in |
|---|---|---|
| 4624 | Successful logon | Brute force/credential stuffing (confirming a hit), lateral movement |
| 4625 | Failed logon | Brute force/credential stuffing (the primary detection source) |
| 4688 | Process creation | Fallback for hosts without Sysmon deployed |
| 4656/4663 | Object access | LSASS access if object auditing is specifically enabled (rare in practice) |
| 7045 | New service installed | Lateral movement (PsExec's core signature) |
| 7036/7040 | Service start/stop | Ransomware (backup service termination) |

**Logon types matter**: type 2 (interactive), type 3 (network, e.g., SMB/lateral movement), type 9 (NewCredentials, e.g., `runas /netonly`), and type 10 (RemoteInteractive/RDP) tell meaningfully different stories about how an account was used — always check logon type, not just success/failure.

## PowerShell logging

Two separate, both needed for full visibility:

- **Event ID 4103 (Module logging)**: which cmdlets ran
- **Event ID 4104 (Script block logging)**: the actual code content, including deobfuscated content in many cases — this is what makes an encoded `-enc` command investigable rather than just suspicious-looking

Script block logging is not enabled by default in most environments — confirming it's on is one of the highest-value baseline checks for any Windows-heavy estate, referenced directly in the PowerShell/LOLBin playbook's detection improvement section.

## WMI-Activity/Operational log

Captures WMI method execution (`ExecMethod`) — necessary specifically because Sysmon's process-based visibility can miss WMI-based lateral movement that doesn't always spawn a traditional child process in the way PsExec does.

## AMSI (Antimalware Scan Interface)

Not a log source on its own — a Windows API that lets antivirus/EDR products inspect script content (PowerShell, VBScript, JScript) before execution, even if the script is obfuscated at the file level. Attackers specifically target AMSI with bypass techniques (patching `AmsiScanBuffer` in memory, reflection against `AmsiUtils`) precisely because it's the choke point standing between an encoded script and detection — referenced in the PowerShell/LOLBin playbook.
