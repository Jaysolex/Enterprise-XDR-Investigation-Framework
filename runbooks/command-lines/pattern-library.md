# Suspicious Command-Line Pattern Library

A quick-reference index of command-line patterns that recur across this repo's playbooks, grouped by what they're used for. Each pattern links to the full playbook explaining triage/validation — this is a fast lookup, not a replacement for reading the full context.

## Obfuscation / execution flags (PowerShell)

| Pattern | What it means | Playbook |
|---|---|---|
| `-enc` / `-EncodedCommand` | Base64-encoded command — not malicious alone, but combined with the flags below is a strong signal | PowerShell/LOLBins |
| `-w hidden` / `-windowstyle hidden` | Suppresses the visible PowerShell window | PowerShell/LOLBins |
| `-nop` / `-noprofile` | Skips the user's PowerShell profile — legitimate scripts rarely need this combined with hidden windows | PowerShell/LOLBins |
| `-ep bypass` | Bypasses execution policy restrictions | PowerShell/LOLBins |

## Download-and-execute patterns

| Pattern | What it means | Playbook |
|---|---|---|
| `IEX (New-Object Net.WebClient).DownloadString(...)` | Fetch and immediately execute remote code without writing to disk | PowerShell/LOLBins |
| `certutil -urlcache -f <url> <file>` | certutil repurposed as a download tool (not its designed function) | PowerShell/LOLBins |
| `certutil -decode <file> <output>` | certutil repurposed to decode a base64-encoded payload (e.g., a disguised executable) | PowerShell/LOLBins |
| `mshta.exe` with inline JavaScript/VBScript | LOLBin proxy execution — mshta is designed to run HTML applications, not arbitrary script snippets | Phishing, PowerShell/LOLBins |
| `regsvr32.exe /i:http://...` | "Squiblydoo" technique — regsvr32 fetching and executing a remote scriptlet | PowerShell/LOLBins |

## Credential access

| Pattern | What it means | Playbook |
|---|---|---|
| `rundll32.exe comsvcs.dll,MiniDump <pid> <file> full` | LSASS memory dump via a built-in DLL export — no third-party tool needed | Credential Dumping |
| `procdump.exe -ma lsass.exe <output>` | Sysinternals procdump targeting LSASS — dual-use, context (account, working directory) determines legitimacy | Credential Dumping |

## Lateral movement / service abuse

| Pattern | What it means | Playbook |
|---|---|---|
| `net use \\host\C$ ...` | Manual SMB share mounting, often immediately preceding PsExec-style service creation | Lateral Movement |
| Service binary path in `\Users\Public\`, `\ProgramData\`, or a temp path | Staged/non-standard location for a "service" — legitimate services are almost always under `C:\Windows\` or `C:\Program Files\` | Lateral Movement |

## Discovery / reconnaissance

| Pattern | What it means | Playbook |
|---|---|---|
| `whoami /all`, `net user`, `net group "Domain Admins" /domain` | Standard orientation commands — individually benign, suspicious in rapid sequence | Recon/Discovery |
| `nltest /domain_trusts` | Domain trust mapping — goes beyond local host info into environment-wide planning | Recon/Discovery |

## Ransomware precursors

| Pattern | What it means | Playbook |
|---|---|---|
| `vssadmin delete shadows /all /quiet` | Shadow copy (recovery point) deletion — near-universal ransomware precursor | Ransomware |
| `wmic shadowcopy delete` | Alternate syntax for the same shadow copy deletion | Ransomware |
| `bcdedit /set {default} recoveryenabled no` | Disables Windows recovery options at boot | Ransomware |

## A note on using this list

None of these patterns are automatically malicious in isolation — the playbooks this list points back to each explain the specific triage questions (account context, timing, combination with other flags, business justification) that separate a real finding from normal admin activity. Treat this file as a fast "does this look familiar" index, and always go back to the full playbook before making a validation call.
