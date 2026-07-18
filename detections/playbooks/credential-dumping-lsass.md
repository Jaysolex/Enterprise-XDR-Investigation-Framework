# Playbook: Credential Dumping via LSASS Access

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)

**Why this one matters:** this is usually the step *before* lateral movement. An attacker lands on a host, dumps credentials out of LSASS, and now has the account they use to hop to the next machine. Treat this playbook and the lateral movement playbook as two halves of the same incident — a credential dump with no follow-on lateral movement is rare, and lateral movement with no credential theft upstream is worth asking "then where did the account come from."

---

## 1. What the detection actually looks like

XDR platforms flag LSASS credential access through a combination of:

- A non-standard process opening a handle to `lsass.exe` with high-privilege access rights (`PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`)
- `comsvcs.dll`'s `MiniDump` export being called against the LSASS process ID — the classic "living off the land" dump method (no Mimikatz binary needed)
- Task Manager, procdump, or a renamed copy of either creating a `.dmp` file
- Sysmon Event ID 10 (ProcessAccess) with `TargetImage` = lsass.exe and a suspicious `GrantedAccess` value (`0x1010`, `0x1410`, `0x1438` are common malicious patterns)
- A newly created `.dmp` file appearing anywhere outside expected crash-dump paths

If the alert just says "credential access detected," you need to know **which mechanism** triggered it before you can investigate — LSASS dumping via API call looks completely different in the logs than a registry-based SAM dump.

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Sysmon Event ID 10 | Process access events — the source process, target (lsass.exe), and the access mask requested |
| Sysmon Event ID 11 | File creation — catches the `.dmp` file being written to disk |
| Sysmon Event ID 1 | Process creation — confirms what spawned the dumping tool and its command line |
| Windows Security Event 4656/4663 | Object access to LSASS if auditing is enabled at the OS level |
| EDR-specific "credential access" telemetry | Most XDR agents hook this directly and will show the API call chain (e.g., `OpenProcess` → `MiniDumpWriteDump`) without needing raw Sysmon |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is the source process a legitimate crash-reporting or diagnostic tool** (Windows Error Reporting, a vendor's support tool) **that has a documented reason to touch LSASS?** Some AV/EDR agents themselves read LSASS memory for legitimate scanning — check your own tooling's baseline first.
2. **Is the access mask consistent with a full memory read**, not just a status check? Low-privilege access requests are usually benign; requests for `PROCESS_VM_READ` combined with `PROCESS_QUERY_INFORMATION` are not normal for anything except a debugger or a dumping tool.
3. **Was a `.dmp` file actually written to disk**, and if so, where? A dump in `%TEMP%`, `C:\Users\Public\`, or a working directory is a strong signal; a dump in `C:\Windows\System32\config\` or CrashDumps under expected OS crash-handling is more likely benign.
4. **Did the source process load `comsvcs.dll` or `dbghelp.dll`/`dbgcore.dll` right before the access?** These are the DLLs that expose dump-writing functions — seeing them loaded by a process with no legitimate reason to load them (e.g., `rundll32.exe`) is close to a smoking gun.

If steps 2–4 point toward malicious, treat this as validated and move straight to scope/containment — don't spend cycles second-guessing at this point, LSASS access is rarely a benign false positive once the access mask and DLL loads line up.

## 4. Investigation: building the process tree

You're answering: *what process reached into LSASS, how did it get there, and did it exfiltrate the dump afterward?*

Typical malicious tree using the living-off-the-land method:
```
cmd.exe
  └── rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\out.dmp full
```

Command-line details that matter:
- `rundll32.exe` calling `comsvcs.dll,MiniDump` with a PID argument is almost never legitimate — this exact syntax is one of the most well-known LOLBin techniques and should be treated as a very high-confidence indicator on its own
- A `procdump.exe` (Sysinternals) invocation against `lsass.exe` is dual-use — legitimate for troubleshooting, but the working directory, the account running it, and whether it was expected all matter
- Look for the dump file being immediately zipped, renamed, or staged for transfer afterward (`Compress-Archive`, `7z a`, or a follow-on network connection to an external host) — that's the difference between "someone ran a risky tool" and "credentials are actively leaving the building"

## 5. Threat validation

Confirm true positive if **two or more** of the following are true:
- The access mask requested against LSASS matches a known dumping pattern (not a benign query)
- `comsvcs.dll`/`MiniDump`, `procdump`, or a known credential-dumping tool signature is present in the command line or loaded modules
- A `.dmp` file was created outside a standard crash-dump location
- The account/process has no documented reason to be touching LSASS (not part of an EDR agent, not a known admin diagnostic workflow)

False positive indicators:
- The process is a recognized, signed EDR/AV agent performing its own legitimate memory scan (check your platform's own documentation for what "normal" looks like)
- A `.dmp` file was created by Windows Error Reporting following an actual LSASS crash, not a deliberate access

## 6. Scope

Once validated, immediately check:
- **What did the dumped credentials get used for?** Pull logons (Event 4624, logon type 9 "NewCredentials" or type 3 "Network") for every account that could plausibly have been in that LSASS memory space, across the environment, starting from the dump time.
- **Did the dump file leave the host?** Check outbound network connections from the source host in the minutes/hours following the dump — this is your bridge into the lateral movement playbook.
- **Is this a domain controller or a high-value server?** LSASS on a DC can expose far more than one user's credentials (potentially cached domain accounts) — scope and urgency both increase sharply if the target host is a DC.

## 7. Containment

Priority order:
1. Network-isolate the host where the dump occurred (preserve state — don't power off, you may need the memory image for forensics).
2. **Assume every credential that could have been in LSASS at dump time is compromised.** This typically means: the interactively logged-on user, any RDP/service accounts that authenticated to that host recently, and (if the host is a DC) potentially cached domain credentials.
3. Force password resets for all affected accounts — don't wait to confirm exact scope, credential dumps are cheap for an attacker to exploit fast.
4. If a Kerberos ticket-based technique is suspected alongside the dump (e.g., golden/silver ticket potential on a DC), loop in whoever owns Active Directory security immediately — this escalates beyond single-host containment.

## 8. Recovery

- Re-image the affected host if the dumping tool indicates broader compromise (not just a one-off credential grab).
- Rotate every credential identified in the scope step, including service accounts — these are often missed and are gold for an attacker to come back to.
- If a domain controller was involved, this is a KRBTGT-account-reset conversation, not just a user password reset — that decision typically sits above analyst level, but you should know to flag it.

## 9. Detection improvement

- If `comsvcs.dll,MiniDump` isn't already an explicit high-fidelity detection rule in your environment, that's a gap worth writing up — it's specific enough to alert on directly rather than relying on generic "process accessed LSASS" noise.
- Consider whether LSASS protection (Credential Guard, RunAsPPL) is enabled fleet-wide — this doesn't stop every technique, but it closes off the easiest ones and is worth flagging as a hardening recommendation, not just a detection one.

## 10. Escalation and handoff notes

When writing this up for the incident ticket or handing off to IR/AD teams:

1. Name the specific mechanism, not just "credential dumping" — comsvcs MiniDump, procdump, registry SAM dump, and DCSync all leave different telemetry and imply different next steps for whoever picks this up.
2. Document the access mask and process lineage exactly as observed — this is what lets a second analyst or IR re-validate your call without re-running the whole investigation from scratch.
3. Always state explicitly in the ticket what you checked for downstream — lateral movement, privilege escalation, further credential use — even if you found nothing, so the next person doesn't have to guess whether that step was done.
4. Containment scope goes in the ticket as **credential-scope-first, not just host-first** — list every account you're recommending for reset and why, not just "isolated the host." Under-scoping the credential reset is the most common way these incidents reopen a week later.
