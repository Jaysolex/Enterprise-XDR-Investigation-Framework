# Telemetry Field Reference

Field-by-field notes on the log sources referenced most often across this repo's playbooks — a quick lookup for what each field actually means when you're staring at a raw log line during an investigation.

## Sysmon Event ID 1 (Process Creation)

| Field | Meaning |
|---|---|
| `Image` | Full path of the process that was created |
| `CommandLine` | The full command line, including arguments — this is the single most important field for almost every playbook in this repo |
| `ParentImage` | Full path of the parent process — this is what builds the process tree |
| `User` | Account context the process ran under |
| `Hashes` | File hashes (SHA256/MD5/IMPHASH) of the executed binary — useful for threat intel lookups |

## Sysmon Event ID 3 (Network Connection)

| Field | Meaning |
|---|---|
| `Image` | Process that initiated the connection |
| `DestinationIp` / `DestinationPort` | Where the connection went |
| `SourceIp` / `SourcePort` | Local side of the connection |
| `Initiated` | Whether this host initiated the connection (true) or received it (false) |

## Sysmon Event ID 10 (Process Access)

| Field | Meaning |
|---|---|
| `SourceImage` | Process doing the accessing |
| `TargetImage` | Process being accessed (e.g., `lsass.exe`) |
| `GrantedAccess` | Hex value representing the access rights requested — specific values (`0x1010`, `0x1410`, `0x1438`) correlate with memory-reading access consistent with credential dumping |

## Windows Security Event 4625 (Failed Logon)

| Field | Meaning |
|---|---|
| `TargetUserName` | Account that failed to authenticate |
| `IpAddress` | Source of the attempt |
| `LogonType` | 2 = interactive, 3 = network, 10 = RemoteInteractive (RDP) — matters for distinguishing attack patterns |
| `FailureReason` / `Status` / `SubStatus` | Why it failed — wrong password vs. account disabled vs. account locked tell different stories |

## Windows Security Event 4624 (Successful Logon)

Same core fields as 4625, plus confirms an attempt actually succeeded — always cross-reference against preceding 4625 events for the same account to determine whether a brute-force/spray attempt eventually landed.

## Windows Security Event 7045 (New Service Installed)

| Field | Meaning |
|---|---|
| `ServiceName` | Name of the newly created service — `PSEXESVC` is the classic PsExec default, but attackers rename this freely |
| `ImagePath` | Path to the service's binary — staged/non-standard paths are a strong signal (see command-line pattern library) |
| `ServiceType` / `StartType` | Additional context, less commonly the deciding factor |

## Zeek conn.log

| Field | Meaning |
|---|---|
| `ts` | Connection start timestamp — the basis for beacon interval analysis |
| `id.orig_h` / `id.resp_h` | Source and destination IP |
| `id.resp_p` | Destination port |
| `duration` | Connection length |
| `orig_bytes` / `resp_bytes` | Data sent/received — the basis for exfiltration volume analysis |

## Zeek dns.log

| Field | Meaning |
|---|---|
| `query` | The domain name queried — check length and entropy for tunneling detection |
| `qtype_name` | Query type (A, TXT, etc.) — TXT records are commonly abused for DNS tunneling due to larger payload capacity per query |
| `answers` | What was returned |

## PowerShell Event ID 4104 (Script Block Logging)

| Field | Meaning |
|---|---|
| `ScriptBlockText` | The actual script content — often deobfuscated by the logging engine even if the invocation was encoded |
| `ScriptBlockId` | Groups multi-part script blocks together for the same execution |

## A note on cross-platform field mapping

Every playbook in this repo includes a query reference section mapping these same underlying concepts to Cortex XDR (XQL), Defender XDR (KQL), CrowdStrike (FQL), Splunk (SPL), and Elastic (EQL) field names — this file describes the concept and native Windows/Zeek field name; the per-playbook query sections handle the vendor-specific translation.
