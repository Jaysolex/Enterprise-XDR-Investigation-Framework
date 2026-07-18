# Everyday CLI Investigation Reference — Windows / Linux / macOS

Quick-reference command cheat sheet for daily SOC investigation work. Format: `command` — `# what it does`. No explanation beyond that — this is a lookup tool, not a teaching doc.

---

## WINDOWS

### Process investigation
```
tasklist /v                                          # list all running processes with details
tasklist /svc                                         # list processes with their hosted services
wmic process list full                                # full process detail dump (path, cmdline, PID/PPID)
wmic process where name="powershell.exe" get commandline,processid   # command line for a specific process
Get-Process | Sort CPU -Descending                     # PowerShell: processes by CPU usage
Get-CimInstance Win32_Process | Select Name,ProcessId,ParentProcessId,CommandLine   # process tree data
taskkill /PID <pid> /F                                 # force-kill a process by PID
```

### Network investigation
```
netstat -ano                                           # all connections with PID
netstat -anob                                          # connections with owning executable (needs admin)
Get-NetTCPConnection | Sort State                      # PowerShell: TCP connections
Get-NetTCPConnection -State Established                # only established connections
ipconfig /all                                           # full network config
ipconfig /displaydns                                    # DNS resolver cache
arp -a                                                  # ARP table (local network mapping)
route print                                             # routing table
nslookup <domain>                                       # DNS lookup
Resolve-DnsName <domain>                                # PowerShell DNS lookup with more detail
```

### User & account investigation
```
whoami /all                                             # current user, groups, privileges
net user                                                # list local accounts
net user <username>                                     # detail on one account
net localgroup administrators                           # list local admin group members
net group "Domain Admins" /domain                       # list domain admins
query user                                              # list logged-on users (RDP sessions)
Get-LocalUser                                            # PowerShell: local accounts
Get-ADUser -Filter * -Properties LastLogonDate           # AD accounts with last logon (needs RSAT)
```

### Logon & authentication
```
net accounts                                             # password/lockout policy
klist                                                    # cached Kerberos tickets
nltest /domain_trusts                                    # domain trust relationships
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20   # recent successful logons
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20   # recent failed logons
```

### Services & persistence
```
sc query                                                 # list all services
sc query state= all                                      # include stopped services
Get-Service | Where Status -eq Running                   # PowerShell: running services
schtasks /query /fo LIST /v                               # scheduled tasks, full detail
Get-ScheduledTask | Where State -eq Ready                 # PowerShell: scheduled tasks
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"   # startup persistence (HKLM)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"   # startup persistence (HKCU)
wmic startup get caption,command                          # startup items via WMI
```

### File system & artifacts
```
dir /s /a /o:d C:\Users\<user>\AppData\Local\Temp        # recently modified temp files, sorted by date
Get-ChildItem -Path C:\ -Recurse -Include *.ps1 -ErrorAction SilentlyContinue   # find PowerShell scripts on disk
Get-FileHash <path> -Algorithm SHA256                     # hash a file for threat intel lookup
Get-ChildItem -Path C:\Users -Filter *.zip -Recurse        # find archive files (staging check)
forfiles /p C:\ /s /d +0 /c "cmd /c echo @path @fdate"    # files modified today, recursively
```

### Shadow copies / recovery (ransomware check)
```
vssadmin list shadows                                     # list existing shadow copies
wmic shadowcopy list brief                                # alternate syntax
```

### Event log quick pulls
```
wevtutil qe Security /c:20 /rd:true /f:text               # last 20 security events, newest first
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 50   # recent PowerShell activity (legacy log)
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50   # script block logging events
```

---

## LINUX

### Process investigation
```
ps aux                                                    # all processes, full detail
ps -ef --forest                                           # process tree view
top -c                                                     # live process view with full command
pstree -p                                                  # process tree with PIDs
lsof -p <pid>                                              # files/sockets opened by a process
cat /proc/<pid>/cmdline                                    # exact command line for a PID
cat /proc/<pid>/status                                     # process status detail (UID, memory, etc.)
kill -9 <pid>                                              # force-kill a process
```

### Network investigation
```
netstat -tulnp                                             # listening ports with owning process
ss -tulnp                                                   # modern replacement for netstat
lsof -i                                                     # all network connections with process
ip a                                                        # network interfaces
ip route                                                    # routing table
arp -a                                                      # ARP table
dig <domain>                                                # DNS lookup
tcpdump -i any -c 100                                       # capture 100 packets on any interface
```

### User & account investigation
```
whoami                                                      # current user
id                                                           # UID/GID and group membership
cat /etc/passwd                                              # local account list
cat /etc/shadow                                              # password hashes (root only)
cat /etc/group                                               # group definitions
last                                                          # login history
lastb                                                         # failed login history
who                                                           # currently logged-in users
w                                                             # logged-in users with active process
```

### Logon & authentication
```
grep "Failed password" /var/log/auth.log                    # failed SSH attempts (Debian/Ubuntu)
grep "Failed password" /var/log/secure                      # failed SSH attempts (RHEL/CentOS)
grep "Accepted password" /var/log/auth.log                  # successful SSH logins
journalctl -u ssh                                            # SSH service logs (systemd)
journalctl _COMM=sshd                                        # SSHD-specific log entries
```

### Services & persistence
```
systemctl list-units --type=service --state=running          # running services
systemctl list-unit-files --state=enabled                    # services enabled at boot
crontab -l                                                    # current user's cron jobs
crontab -l -u <user>                                          # another user's cron jobs (root needed)
cat /etc/crontab                                              # system-wide cron
ls -la /etc/cron.d/                                           # additional cron drop-ins
cat ~/.bashrc ~/.profile ~/.bash_profile                      # shell startup persistence check
cat ~/.ssh/authorized_keys                                    # check for unauthorized SSH keys
```

### File system & artifacts
```
find / -mmin -60 -type f 2>/dev/null                          # files modified in the last 60 minutes
find / -newer /etc/passwd -type f 2>/dev/null                  # files newer than a reference file
sha256sum <path>                                               # hash a file for threat intel lookup
find /tmp /var/tmp /dev/shm -type f 2>/dev/null                # check common staging directories
lsattr <path>                                                  # check immutable/hidden file attributes
stat <path>                                                    # full file metadata (timestamps, permissions)
```

### Log locations quick reference
```
/var/log/auth.log          # authentication log (Debian/Ubuntu)
/var/log/secure            # authentication log (RHEL/CentOS)
/var/log/syslog            # general system log (Debian/Ubuntu)
/var/log/messages          # general system log (RHEL/CentOS)
/var/log/audit/audit.log   # auditd log, if configured
journalctl -xe             # recent systemd journal, most verbose
```

---

## macOS

### Process investigation
```
ps aux                                                       # all processes, full detail
ps -ef                                                        # alternate syntax with PPID
top -o cpu                                                    # live process view sorted by CPU
lsof -p <pid>                                                 # files/sockets opened by a process
launchctl list                                                # list loaded launch agents/daemons
```

### Network investigation
```
netstat -anv                                                  # connections with verbose detail
lsof -i                                                        # network connections with owning process
ifconfig                                                       # network interfaces (macOS still uses this)
netstat -rn                                                    # routing table
arp -a                                                          # ARP table
dig <domain>                                                   # DNS lookup
tcpdump -i en0 -c 100                                           # capture 100 packets on primary interface
```

### User & account investigation
```
whoami                                                         # current user
id                                                              # UID/GID and groups
dscl . -list /Users                                              # list all user accounts
dscl . -read /Users/<user>                                       # detail on one account
last                                                             # login history
who                                                              # currently logged-in users
```

### Logon & authentication
```
log show --predicate 'eventMessage contains "authentication"' --last 1h   # recent auth events (unified logging)
log show --predicate 'process == "sshd"' --last 1h              # SSH-related events
```

### Services & persistence (the macOS-specific area that matters most)
```
launchctl list                                                   # loaded launch agents/daemons
ls -la ~/Library/LaunchAgents/                                    # user-level persistence location
ls -la /Library/LaunchAgents/                                     # system-wide, per-user persistence
ls -la /Library/LaunchDaemons/                                    # system-wide, root-level persistence — highest-value check
osascript -e 'tell application "System Events" to get the name of every login item'   # login items (GUI-configured persistence)
crontab -l                                                        # cron jobs (less common on macOS but still checked)
```

### File system & artifacts
```
find / -mtime -1 -type f 2>/dev/null                              # files modified in the last day
shasum -a 256 <path>                                               # hash a file for threat intel lookup (macOS uses shasum, not sha256sum)
mdfind -name "<filename>"                                          # Spotlight-indexed file search, fast
xattr -l <path>                                                    # extended attributes, including quarantine flag (shows download origin)
find /tmp /private/tmp -type f 2>/dev/null                         # check common staging directories
```

### Gatekeeper / quarantine check (unique to macOS — tells you if a file was downloaded and from where)
```
xattr -p com.apple.quarantine <path>                               # shows quarantine flag detail if present — absence can indicate the file bypassed normal download flow
spctl -a -v <path>                                                  # check Gatekeeper assessment on a binary
```

### Log locations quick reference
```
log show --last 1h                          # unified logging, last hour, all subsystems
/var/log/system.log                          # legacy system log (less used since unified logging)
~/Library/Logs/                              # user-level application logs
/Library/Logs/                               # system-wide application logs
```

---

## Cross-platform notes

- **Windows** command-line investigation leans on Sysmon/Event Logs for depth — native commands above give you a live snapshot, but historical/forensic detail comes from the event log queries in the playbooks folder of this repo.
- **Linux** persistence checks (cron, `.bashrc`, `authorized_keys`) should always be run as part of any host investigation — these are the first three places a foothold gets re-established after a host is "cleaned."
- **macOS** persistence is almost entirely LaunchAgents/LaunchDaemons — check `/Library/LaunchDaemons/` first since it runs as root and is the highest-value target for anything trying to survive a reboot.
- All three: **always hash suspicious files before deleting them** — you lose the ability to check threat intel once the artifact is gone.
