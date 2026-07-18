# Linux Telemetry Reference

Background on Linux-side telemetry sources — less directly referenced in this repo's current playbooks (which are Windows-heavy, reflecting the more common enterprise attack surface), but foundational if extending the framework to cover Linux-specific techniques.

## auditd

The standard Linux kernel-level audit framework — closest Linux equivalent to Windows Security auditing.

- **Syscall auditing**: rules can be set to log specific syscalls (`execve`, `open`, `connect`) with full argument detail
- **Watch rules**: monitor specific files/directories for access (`-w /etc/passwd -p wa` logs writes/attribute changes to `/etc/passwd`)
- Output goes to `/var/log/audit/audit.log`, parseable directly or shipped to a SIEM

Key limitation: auditd has no native process-tree/parent-child correlation the way Sysmon does — reconstructing a process tree from raw auditd logs requires manually correlating PID/PPID fields across separate `execve` records, which is more manual work than the Windows equivalent.

## eBPF-based tooling (Falco, Tetragon, and similar)

Increasingly the preferred approach over raw auditd for real-time detection, because eBPF programs can attach to kernel events with much lower overhead and richer context than auditd's older framework.

- **Falco**: rule-based runtime security, ships with a substantial default ruleset for common attack patterns (shell spawned in container, sensitive file access, etc.)
- Provides process ancestry natively, closer to Sysmon's model than raw auditd

## syslog / journald

Application and system-level logging — the closest analog to "everything else," covering authentication (`/var/log/auth.log` or journald's auth facility), cron execution, and service-level events.

- SSH authentication attempts (relevant to the brute-force/credential-stuffing playbook if extended to cover Linux targets) live here: `Failed password for <user> from <ip>` / `Accepted password for <user> from <ip>`

## Key differences from the Windows model used elsewhere in this repo

- No direct Sysmon equivalent bundled as one tool — auditd + eBPF tooling + syslog together cover roughly the same ground Sysmon covers alone on Windows
- Process command-line visibility is native via auditd's `execve` records (no separate "enable command-line logging" step required, unlike Windows Event 4688)
- Persistence mechanisms differ substantially from Windows (cron jobs, systemd units, `.bashrc`/`.profile` modifications, SSH authorized_keys tampering) rather than registry Run keys or scheduled tasks — worth a dedicated playbook if this repo is extended to cover Linux-targeted persistence specifically
