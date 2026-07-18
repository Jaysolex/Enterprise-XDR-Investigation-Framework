# CLI Investigation Reference v2 — Deep Dive + Automation

Extends the base cheat sheet with: Linux `/proc` internals, rsyslog specifics, Windows internals (registry/WMI/ETW), and working Python/Bash automation scripts. Every section maps directly to SPL (Splunk) and KQL (Defender/Sentinel) equivalents so you can go from "ran it by hand" to "wrote the detection" without re-deriving the logic.

---

## LINUX — /proc DEEP DIVE

`/proc` is a live, in-memory filesystem — every number under it is a running PID. This is the ground truth when a process claims to be something it isn't (renamed binary, deleted-but-running file).

```
ls /proc/<pid>/                       # everything the kernel knows about a running process
cat /proc/<pid>/cmdline               # exact command line, null-byte separated (use `tr '\0' ' '` to read)
cat /proc/<pid>/cmdline | tr '\0' ' '; echo   # same, human-readable
readlink /proc/<pid>/exe              # actual binary path — catches processes running from a deleted/renamed file
cat /proc/<pid>/status                # UID/GID, memory, thread count, signal masks
cat /proc/<pid>/environ | tr '\0' '\n'  # environment variables the process was launched with — often reveals staging paths
ls -la /proc/<pid>/fd/                # every open file descriptor — sockets, pipes, open files
readlink /proc/<pid>/cwd              # current working directory of the process
cat /proc/<pid>/maps                  # memory-mapped regions — libraries loaded, useful for injected-code detection
cat /proc/net/tcp                     # raw TCP table (hex-encoded — cross-reference with ss for readability)
for p in /proc/[0-9]*; do echo "$p: $(cat $p/comm 2>/dev/null)"; done   # quick PID-to-name sweep, no ps needed
```

**Why this matters over `ps`**: `ps` reads from `/proc` too, but a sufficiently short-lived or intentionally obscured process can be caught in `/proc` before `ps` refreshes, and `readlink /proc/<pid>/exe` specifically defeats the classic "rename malware.bin to systemd-something" trick — the symlink still points to the real inode even after rename or deletion.

## LINUX — rsyslog SPECIFICS

Most Linux log routing goes through rsyslog (or its config-compatible cousin syslog-ng) before landing in `/var/log/*`. Knowing where it's configured and how to query its output live matters for anything beyond "cat a static file."

```
cat /etc/rsyslog.conf                          # main config — see what's being logged where
ls /etc/rsyslog.d/                              # modular config drop-ins, often where custom rules live
rsyslogd -N1                                     # validate rsyslog config syntax without restarting
systemctl status rsyslog                         # confirm the service is actually running (a stopped rsyslog = silent logging gap)
logger "test message from $(hostname)"           # inject a test message to confirm end-to-end logging works
tail -f /var/log/syslog | grep -i "authentication\|sudo\|ssh"   # live-tail filtered for auth-relevant events
```

**Facility/priority quick reference** (used in rsyslog.conf rules like `auth,authpriv.* /var/log/auth.log`):
```
auth / authpriv    # authentication-related messages — this is the facility that feeds /var/log/auth.log
kern               # kernel messages
cron               # cron daemon messages
daemon             # generic background service messages
local0–local7      # custom-defined facilities, often used by security tools for their own logging
```

If a host's `/var/log/auth.log` looks suspiciously empty or stale, check `rsyslogd -N1` and `systemctl status rsyslog` before assuming there's simply no activity — a disabled or crashed rsyslog is itself a finding (possible log-tampering/defense-evasion, MITRE T1070.002).

---

## WINDOWS INTERNALS — DEEPER

### Registry (beyond basic Run keys)
```
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr ImagePath   # every service's binary path in one pull
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell   # Winlogon Shell value — classic persistence target
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s   # IFEO debugger hijacking check
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"          # one-time-run persistence, easy to miss
reg query "HKLM\Software\Classes\ms-settings\shell\open\command"            # UAC bypass artifact location (fodhelper-style)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections   # check if RDP is actually enabled at the registry level
```

### WMI (deeper than a basic process list)
```
Get-WmiObject -Namespace root\subscription -Class __EventFilter            # WMI event subscriptions — a fileless persistence mechanism, check this every time
Get-WmiObject -Namespace root\subscription -Class __EventConsumer          # paired half of the above — the action taken when the filter fires
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding   # links the filter to the consumer — the full persistence chain
wmic /namespace:\\root\subscription PATH __EventFilter GET Name,Query      # command-line equivalent for the filter side
```
**Why this matters**: WMI event subscriptions are one of the most common fileless persistence techniques (no scheduled task, no Run key, no service) — if you only check the standard persistence locations and skip this, you will miss it.

### ETW (Event Tracing for Windows) — quick context
```
logman query providers                                                      # list all ETW providers available on the host
logman query -ets                                                           # list actively running trace sessions
Get-WinEvent -ListProvider "Microsoft-Windows-PowerShell"                    # confirm a specific provider's event ID catalog
```
ETW is the underlying mechanism Sysmon, PowerShell script block logging, and most modern EDR agents build on — knowing it exists helps you understand why an event log has the fields it does, and how to confirm whether a specific provider is actually generating events before assuming "no alerts" means "no activity."

### Prefetch (execution evidence, survives a while after deletion)
```
dir C:\Windows\Prefetch\*.pf                                                # list prefetch files — evidence a binary was executed, even if since deleted
Get-ChildItem C:\Windows\Prefetch -Filter *.pf | Sort LastWriteTime -Descending   # sorted by most recent execution
```

### Amcache / Shimcache context (mention — needs specialist parsing tools, not raw CLI)
`Amcache.hve` (`C:\Windows\AppCompat\Programs\Amcache.hve`) and the Shimcache (in the registry, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`) both retain evidence of binary execution/presence even after deletion. These require a parser (e.g., `AmcacheParser`, `AppCompatCacheParser` from Eric Zimmerman's tools) rather than a raw `reg query` — flagging their existence here since they're a common gap in "I checked everything" claims during an investigation.

---

## AUTOMATION — PYTHON LOG PARSERS

### Windows Security Event Log (EVTX) — failed/successful logon summary
```python
#!/usr/bin/env python3
"""
Parse a Windows Security EVTX export (as CSV via wevtutil or Get-WinEvent | Export-Csv)
and summarize failed vs successful logons by account and source IP.
Usage: python3 logon_summary.py security_events.csv
"""
import csv
import sys
from collections import defaultdict

def main(csv_path):
    failed = defaultdict(int)
    success = defaultdict(int)

    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get('Id') or row.get('EventID')
            user = row.get('TargetUserName', 'UNKNOWN')
            ip = row.get('IpAddress', 'UNKNOWN')
            key = (user, ip)

            if event_id == '4625':
                failed[key] += 1
            elif event_id == '4624':
                success[key] += 1

    print("=== Failed logon attempts (account, source_ip): count ===")
    for key, count in sorted(failed.items(), key=lambda x: -x[1]):
        print(f"{key}: {count}")

    print("\n=== Successful logons (account, source_ip): count ===")
    for key, count in sorted(success.items(), key=lambda x: -x[1]):
        print(f"{key}: {count}")

    # Flag accounts with high failure count followed by any success — potential brute-force hit
    print("\n=== Accounts with failures AND a success (possible compromise) ===")
    for (user, ip), fail_count in failed.items():
        if any(u == user for (u, _) in success):
            print(f"{user} from {ip}: {fail_count} failures, then succeeded")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 logon_summary.py <csv_path>")
        sys.exit(1)
    main(sys.argv[1])
```
**To generate the input CSV:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 5000 |
  Select-Object TimeCreated, Id, @{n='TargetUserName';e={$_.Properties[5].Value}}, @{n='IpAddress';e={$_.Properties[19].Value}} |
  Export-Csv security_events.csv -NoTypeInformation
```

### Sysmon process-tree reconstructor (from EVTX-exported CSV)
```python
#!/usr/bin/env python3
"""
Reconstruct a process tree from a Sysmon Event ID 1 CSV export.
Usage: python3 process_tree.py sysmon_events.csv
"""
import csv
import sys
from collections import defaultdict

def main(csv_path):
    children = defaultdict(list)
    proc_info = {}

    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            pid = row.get('ProcessId')
            ppid = row.get('ParentProcessId')
            image = row.get('Image', '?')
            cmdline = row.get('CommandLine', '')
            proc_info[pid] = (image, cmdline)
            children[ppid].append(pid)

    def print_tree(pid, depth=0):
        image, cmdline = proc_info.get(pid, ('?', ''))
        print('  ' * depth + f"└─ {image} (PID {pid})")
        if cmdline:
            print('  ' * (depth + 1) + f"   cmd: {cmdline}")
        for child_pid in children.get(pid, []):
            print_tree(child_pid, depth + 1)

    # Find roots — processes whose parent PID isn't itself in the dataset
    all_pids = set(proc_info.keys())
    roots = [pid for pid in all_pids if row.get('ParentProcessId') not in all_pids]

    for root in set(roots):
        print_tree(root)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 process_tree.py <csv_path>")
        sys.exit(1)
    main(sys.argv[1])
```

### Linux auth.log brute-force detector
```python
#!/usr/bin/env python3
"""
Scan a Linux auth.log for brute-force / password-spray patterns.
Usage: python3 auth_log_scan.py /var/log/auth.log
"""
import re
import sys
from collections import defaultdict

FAILED_RE = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')
SUCCESS_RE = re.compile(r'Accepted password for (\S+) from (\S+)')

def main(log_path):
    failed_by_user = defaultdict(int)
    failed_by_ip = defaultdict(set)   # IP -> set of usernames attempted (spray detection)
    successes = []

    with open(log_path, errors='ignore') as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                user, ip = m.groups()
                failed_by_user[user] += 1
                failed_by_ip[ip].add(user)
                continue
            m = SUCCESS_RE.search(line)
            if m:
                successes.append(m.groups())

    print("=== Classic brute force (many failures, one account) ===")
    for user, count in sorted(failed_by_user.items(), key=lambda x: -x[1]):
        if count > 10:
            print(f"{user}: {count} failed attempts")

    print("\n=== Password spray (few failures per account, many accounts, one source) ===")
    for ip, users in failed_by_ip.items():
        if len(users) > 10:
            print(f"{ip}: attempted {len(users)} different accounts")

    print("\n=== Successful logins (cross-reference against the above) ===")
    for user, ip in successes:
        flagged = " <-- FLAGGED: also appears in failure list" if user in failed_by_user else ""
        print(f"{user} from {ip}{flagged}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 auth_log_scan.py <path_to_auth.log>")
        sys.exit(1)
    main(sys.argv[1])
```

---

## AUTOMATION — BASH LOG PARSERS

### Quick failed-SSH-attempt summary, one-liner
```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3), $(NF-1)}' | sort | uniq -c | sort -rn
# output: count, username, source_ip — sorted highest first
```

### Password spray detector (many accounts, one source IP)
```bash
#!/bin/bash
# spray_check.sh — flags source IPs that attempted more than 10 distinct accounts
LOGFILE="${1:-/var/log/auth.log}"

grep "Failed password" "$LOGFILE" | \
  awk '{print $(NF-1), $(NF-3)}' | \
  sort -u | \
  awk '{count[$1]++} END {for (ip in count) if (count[ip] > 10) print ip, count[ip], "distinct accounts attempted"}'
```

### Recently modified files sweep (staging/exfil precursor check)
```bash
#!/bin/bash
# recent_files.sh — files modified in the last N minutes across common staging directories
MINUTES="${1:-60}"

for dir in /tmp /var/tmp /dev/shm /home/*/Downloads; do
  find "$dir" -mmin -"$MINUTES" -type f 2>/dev/null
done | sort
```

### Cron/persistence sweep across all users
```bash
#!/bin/bash
# cron_sweep.sh — dump every user's crontab in one pass
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null | sed "s/^/[$user] /"
done
```

### Quick process-to-network correlation (what's talking to the network right now)
```bash
#!/bin/bash
# proc_net_correlate.sh — for every listening/established connection, show the owning process
ss -tulnp 2>/dev/null | tail -n +2 | while read -r line; do
  pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+')
  if [ -n "$pid" ]; then
    cmd=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)
    echo "$line | CMD: $cmd"
  fi
done
```

---

## SPL (Splunk) — MAPPED TO EVERY CATEGORY ABOVE

**Failed/successful logons (matches the Python logon_summary.py logic natively)**
```spl
index=main (EventCode=4624 OR EventCode=4625)
| eval result=if(EventCode=4625, "failed", "success")
| stats count by TargetUserName, IpAddress, result
| sort -count
```

**Password spray detection**
```spl
index=main EventCode=4625
| stats dc(TargetUserName) as unique_accounts by IpAddress
| where unique_accounts > 10
```

**Process tree reconstruction (Sysmon)**
```spl
index=main sourcetype=sysmon EventCode=1
| table _time, ComputerName, Image, ParentImage, CommandLine, ProcessId, ParentProcessId
| sort _time
```

**WMI persistence check (if WMI-Activity log is ingested)**
```spl
index=main source="*WMI-Activity/Operational*"
| search EventCode=5861 OR EventCode=5859
| table _time, ComputerName, Message
```

**Linux auth log brute force (if syslog/auth.log is ingested)**
```spl
index=linux sourcetype=syslog "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count by user, src_ip
| where count > 10
```

**Recently created/modified files (if file monitoring is ingested)**
```spl
index=main sourcetype=filemonitor
| where earliest=-1h
| table _time, ComputerName, FilePath, Action
```

---

## KQL (Microsoft Sentinel / Defender XDR) — MAPPED TO EVERY CATEGORY ABOVE

**Failed/successful logons**
```kql
SigninLogs
| summarize FailCount = countif(ResultType != 0), SuccessCount = countif(ResultType == 0) by UserPrincipalName, IPAddress
| order by FailCount desc
```

**Password spray detection**
```kql
SigninLogs
| where ResultType != 0
| summarize UniqueAccounts = dcount(UserPrincipalName) by IPAddress
| where UniqueAccounts > 10
```

**Process tree reconstruction**
```kql
DeviceProcessEvents
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId, InitiatingProcessId
| order by Timestamp asc
```

**WMI persistence check**
```kql
DeviceEvents
| where ActionType has "WmiEventFilter" or ActionType has "WmiEventConsumer"
| project Timestamp, DeviceName, ActionType, AdditionalFields
```

**Linux auth log brute force (via Microsoft Sentinel's Syslog connector)**
```kql
Syslog
| where SyslogMessage has "Failed password"
| parse SyslogMessage with * "Failed password for " User " from " SourceIP " " *
| summarize count() by User, SourceIP
| where count_ > 10
```

**Recently modified files**
```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```

**Registry persistence check (Run keys, Winlogon Shell, IFEO)**
```kql
DeviceRegistryEvents
| where RegistryKey has_any ("CurrentVersion\\Run", "Winlogon", "Image File Execution Options")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

---

## Cross-platform notes (updated)

- **Windows**: WMI event subscriptions (`__EventFilter`/`__EventConsumer`) are the single most commonly missed persistence check — they leave no scheduled task, no Run key, and no service, and standard sweeps skip them unless explicitly included.
- **Linux**: `/proc/<pid>/exe` via `readlink` is the ground-truth check that defeats renamed/deleted-but-running malware — `ps` alone can be fooled more easily than the `/proc` filesystem itself.
- **rsyslog silence is itself a finding** — a host with an unexpectedly empty or stale `auth.log` should trigger a check of the logging service itself, not just an assumption of no activity (MITRE T1070.002, indicator removal).
- **All Python/Bash scripts above are starting points**, not production tooling — they assume relatively clean input (standard log formats, UTF-8, no unusual field ordering) and should be adjusted to your actual environment's log format before relying on them at scale.
- **SPL/KQL mappings are 1:1 conceptual equivalents** of the manual commands above them — running the manual command teaches you what the data looks like; the query automates finding it at scale once you already understand what "normal" and "abnormal" look like in that data.
