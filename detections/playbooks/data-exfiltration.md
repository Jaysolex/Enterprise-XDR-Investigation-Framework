# Playbook: Data Exfiltration

**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service), T1048 (Exfiltration Over Alternative Protocol)

**Where this sits in the chain:** this is the payoff stage. Once C2 is established, the attacker's objective is usually data — this playbook is what you run when you need to answer "did anything actually leave," which is often the single most important question in an entire incident, and the one stakeholders outside security care about most directly.

---

## 1. What the detection actually looks like

- A sudden spike in outbound data volume from a single host, especially outside normal business hours
- Large outbound transfers to cloud storage/file-sharing services (which are often allowlisted for legitimate business use, making this harder to distinguish from normal traffic — this is the central challenge of this playbook)
- Data staged into a single archive (`.zip`, `.rar`, `.7z`) shortly before the transfer — staging is a strong precursor signal even before the transfer itself is observed
- DNS tunneling patterns: unusually high volume or unusually long subdomain labels in DNS queries to a single domain (data encoded into DNS queries to evade normal network monitoring)
- Outbound transfer over a non-standard port, or over a protocol not normally used by the source process

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Zeek `conn.log` | Byte counts (orig_bytes/resp_bytes) per connection — the foundation for volume-based detection |
| Proxy logs | Destination URL/domain, upload volume, user agent — critical for distinguishing legitimate cloud service use from exfiltration |
| DLP (Data Loss Prevention) alerts | Content-based matches (classified documents, PII patterns, source code) actually leaving |
| Sysmon Event ID 11 | File creation — catches archive files being staged before transfer |
| DNS logs | Query volume and subdomain length/entropy for tunneling detection |
| Cloud storage audit logs (if applicable) | Upload events to sanctioned cloud storage that might be misused for exfiltration |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is the destination a sanctioned business tool** (the company's own approved cloud storage, a known business partner)? If so, is the *volume* and *timing* still consistent with normal use, or does it stand out (large transfer at 3 AM to a personal cloud storage account rather than the corporate tenant)?
2. **Was an archive created immediately before the transfer?** Staging is one of the strongest signals in this entire playbook — legitimate large transfers are rarely preceded by the user manually compressing a folder into a single archive right before uploading it.
3. **Does the transfer correlate with any of the earlier stages of this chain** (a host already flagged for C2 beaconing, lateral movement, or credential access)? If yes, treat the volume/timing question as far less relevant — a confirmed-compromised host transferring any meaningful volume of data outbound is a validated concern regardless of destination.
4. **Is DLP flagging actual sensitive content**, or only volume/destination anomalies? A DLP content match is a much stronger signal on its own than volume alone.

If the host is already part of a confirmed incident chain (credential access → lateral movement → C2), any subsequent outbound data transfer of meaningful size should be treated as validated exfiltration pending investigation, not triaged from scratch as if unrelated.

## 4. Investigation: confirming what left and how much

You're answering: *what was taken, how much, and by what path.*

**Volume/timing analysis from Zeek conn.log:**
```bash
zcat conn.log.gz | zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes \
  | awk '$5 > 10000000' \
  | sort -k5 -n -r
```
(Adjust the byte threshold to what's abnormal for your environment — this flags connections with unusually large outbound transfer volumes.)

**Confirming staging on the host:**
```
Sysmon Event ID 11: file created — <username>_backup.zip in a temp/staging directory
  → shortly followed by →
Sysmon Event ID 3: network connection, large orig_bytes, destination = <cloud storage or unusual endpoint>
```

Details that matter:
- **Archive naming and location**: attacker-staged archives are often placed in temp directories or the same directory the sensitive data already lived in, and named innocuously (`backup.zip`, `update.zip`) rather than descriptively
- **Timing relative to business hours**: a large transfer at 2 AM local time from a host with no history of after-hours activity is a much stronger signal than the same transfer during the workday
- **Destination reputation and account context**: uploads to a personal (non-corporate-tenant) instance of an otherwise-legitimate cloud storage provider are a common technique specifically because the domain itself is allowlisted

## 5. Threat validation

Confirm true positive if **two or more** of the following are true:
- Archive staging observed immediately before an unusually large outbound transfer
- Destination is not the sanctioned corporate instance of an allowlisted service (personal account, different tenant)
- DLP flagged actual sensitive content in the transferred data
- The host is already part of a confirmed incident chain from an earlier stage

False positive indicators:
- Transfer matches a known, scheduled business process (backup job, legitimate data sync) and destination is the sanctioned corporate tenant
- Volume anomaly with no staging, no DLP hit, and no connection to any other suspicious activity on the host

## 6. Scope

Once validated:
- **Identify exactly what was in the staged archive** if still recoverable from disk or backups — this is often the single most important fact for downstream legal/compliance/breach-notification decisions, and worth prioritizing even under time pressure.
- **Check whether the same exfiltration pattern (destination, method, timing) appears on any other host** in the environment — if this was a scripted/automated exfiltration technique, it may have been run against multiple targets.
- **Correlate against the full incident chain** — this stage typically closes out a narrative that started with phishing or credential theft, so scope here should reference every earlier stage's findings rather than being assessed in isolation.

## 7. Containment

Priority order:
1. Block the destination (domain/IP/cloud storage endpoint) at the network layer to stop further transfer.
2. Revoke any active sessions/tokens for accounts involved, consistent with earlier playbooks in this chain.
3. If the destination is a legitimate cloud service being abused (personal tenant of an allowlisted provider), this often requires a policy-level block (e.g., blocking personal-tenant uploads specifically while still allowing corporate-tenant use) rather than a blanket domain block — loop in whoever owns the proxy/CASB policy.

## 8. Recovery

- Recovery here is less about the host (follow whichever earlier playbook's recovery steps apply for the compromised endpoint) and more about downstream response: legal/compliance notification requirements depend entirely on what data was confirmed exfiltrated, which is why scoping "what left" precisely matters more in this playbook than in any of the others.
- If credentials were involved anywhere in the chain, ensure rotation already completed in the credential-dumping playbook's containment step is still valid — exfiltration is often the last confirmed stage of an incident, so this is a good checkpoint to verify nothing upstream was missed.

## 9. Detection improvement

- If your environment doesn't already distinguish between sanctioned-tenant and personal-tenant use of common cloud storage/collaboration platforms (a CASB or proxy-level policy), that's a significant detection gap — this exact "legitimate service, wrong tenant" pattern is one of the most common real-world exfiltration methods precisely because it hides in already-allowlisted traffic.
- DNS tunneling detection (query volume and subdomain entropy) is worth having as a standing rule even if you haven't seen it triggered yet — it's a technique specifically chosen to evade standard proxy/DLP monitoring.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter action_total_upload > 10000000
| fields agent_hostname, action_remote_ip, action_remote_port, action_total_upload, _time
| sort desc action_total_upload
```

**Microsoft Defender XDR (KQL / Advanced Hunting)**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| summarize TotalBytesOut = sum(BytesOut) by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalBytesOut > 10000000
| order by TotalBytesOut desc
```
Archive staging just before transfer:
```kql
DeviceFileEvents
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| where FolderPath has_any ("Temp", "AppData", "Public")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

**CrowdStrike Falcon (Event Search / Falcon Query Language)**
```
event_simpleName=NetworkConnectIP4
| stats sum(SendBytes) as TotalSent by ComputerName, RemoteAddressIP4
| where TotalSent > 10000000
```

**Splunk (Zeek conn.log)**
```spl
index=zeek sourcetype=zeek_conn
| where orig_bytes > 10000000
| table _time, id.orig_h, id.resp_h, id.resp_p, orig_bytes, resp_bytes
| sort -orig_bytes
```

**Elastic (EQL / aggregation query)**
```eql
network where network.bytes > 10000000
```
Better handled as a Kibana aggregation on `source.bytes` grouped by `destination.ip` and `host.name` for volume ranking across a time window.

## 11. Escalation and handoff notes

When writing this up for the incident ticket:
1. State the confirmed data volume and, if recoverable, the actual content/classification of what was staged — vague descriptions ("some files may have left") create major downstream problems for legal/compliance decisions that depend on precise scoping.
2. Note explicitly whether the destination was a sanctioned service misused (wrong tenant) versus genuinely unknown infrastructure — the response and policy implications differ significantly.
3. Reference every earlier stage of the incident chain this connects to (phishing origin, credential access, lateral movement, C2) so the ticket reads as one complete narrative rather than an isolated network anomaly.
4. Flag immediately, outside the ticket itself, if data with legal/compliance/breach-notification implications (PII, regulated data categories) was confirmed exfiltrated — this often has time-sensitive reporting obligations that shouldn't wait for the ticket to be fully written up.
