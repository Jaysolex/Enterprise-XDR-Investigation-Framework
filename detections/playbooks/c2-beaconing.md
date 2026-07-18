# Playbook: Command-and-Control (C2) Beaconing Detection

**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1568 (Dynamic Resolution)

**Where this sits in the chain:** by this point the attacker has credentials, lateral access, and staged execution capability (previous three playbooks). C2 beaconing is how they maintain a persistent, ongoing channel back to infrastructure they control — this is what turns a one-time compromise into an ongoing one. Unlike the previous three playbooks, this one is detected almost entirely through **network telemetry**, not host telemetry — a genuinely different investigative skill, and one that's easy to neglect if you've only worked EDR-centric alerts.

---

## 1. What the detection actually looks like

C2 beaconing rarely looks like a single alarming event — it looks like a **pattern over time**:

- Regular, low-jitter outbound connections at consistent intervals (every 60s, every 300s) — real user traffic is bursty and irregular; beacons are metronomic
- Small, consistent payload sizes on each connection — a beacon "check-in" is usually a small fixed-size request even if the response varies
- Connections to a domain with a very recently registered certificate, or a domain using domain generation algorithm (DGA)-style naming
- TLS traffic to an IP with no corresponding legitimate reverse DNS or hosting reputation
- Long-lived connections with periodic small keepalive-style data transfers, consistent with an actively tasked implant rather than a one-time download

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Zeek `conn.log` | Every connection with duration, byte counts, and interval — the foundation for beacon interval analysis |
| Zeek `ssl.log` / `x509.log` | Certificate details — issuer, validity period, self-signed indicators |
| Zeek `dns.log` | Query patterns — high entropy/DGA-style names, unusually high query volume to one domain |
| Sysmon Event ID 3 | Ties a network connection back to the originating process on the host |
| Suricata/IDS alerts | Signature-based hits for known C2 frameworks (Cobalt Strike default profiles, known JA3/JA3S hashes) |
| NetFlow/firewall logs | Connection frequency and volume over time, useful for beacon interval analysis at scale across many hosts |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is the destination a known-good service** (cloud provider API, telemetry/update endpoint, SaaS backend)? Many legitimate applications also beacon regularly — Slack, Teams, antivirus check-ins, Windows Update all produce periodic traffic. Check the destination reputation and whether the process making the connection is expected to talk to it.
2. **Is the interval too regular to be human-driven, but the destination isn't a known legitimate service?** This combination — high regularity, low reputation, unexplained destination — is the strongest signal.
3. **What process on the host is making the connection?** A browser or known application talking to an unusual domain is different from `powershell.exe`, `rundll32.exe`, or an unsigned binary making the connection directly.
4. **Does the certificate look suspicious** — self-signed, very recently issued, or issued for a domain with no other legitimate content?

If the interval is regular, the process is unusual, and the destination has poor reputation, escalate directly to full investigation — beacon patterns rarely resolve as false positives once two or more of these line up.

## 4. Investigation: confirming a beacon pattern

You're answering: *is this actually periodic, and does it tie back to a process that has no legitimate reason to be making this connection?*

**Manual interval check from Zeek conn.log** (rough approach — pull connection timestamps to the same destination and check spacing):
```bash
zcat conn.log.gz | zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | awk '$3 == "<suspect_destination_ip>"' \
  | sort -n
```
Look at the `ts` (timestamp) column spacing between consecutive rows — real beaconing shows near-constant deltas (e.g., every ~60 seconds ± a few seconds of jitter), where legitimate user browsing shows highly irregular gaps.

Process tree correlation — tie the network connection back to what's making it:
```
powershell.exe (or an unsigned/renamed binary)
  └── outbound connection every ~60s to <ip>:443
        → small consistent payload size each time
        → certificate self-signed or issued days before observation
```

Details that matter:
- **Jitter percentage**: real C2 frameworks often add randomized jitter (e.g., ±20%) specifically to evade naive "exact interval" detection — don't dismiss a pattern just because the intervals aren't perfectly identical, look at whether they cluster tightly around a mean
- **JA3/JA3S hashes**: these fingerprint the TLS client/server handshake behavior and can match known C2 framework defaults (Cobalt Strike, Sliver, Metasploit) even over encrypted traffic where you can't see payload content
- **Domain age and certificate issuance date**: a domain registered days ago with a certificate issued the same week is a strong indicator regardless of what the traffic content looks like

## 5. Threat validation

Confirm true positive if **two or more** of the following are true:
- Connection interval is statistically regular (tight clustering around a mean, even with jitter) and doesn't match known legitimate application behavior
- Destination has poor or no reputation, a newly registered domain, or a JA3/JA3S match to known C2 tooling
- The originating process has no legitimate reason to make external connections (a LOLBin, an unsigned binary, or a process already flagged in an earlier stage of this same incident)
- Certificate is self-signed or was issued suspiciously close to first observed traffic

False positive indicators:
- Destination matches a known SaaS/cloud/update endpoint and the originating process is the expected application for that traffic
- Interval is regular but explained by a documented monitoring/heartbeat agent

## 6. Scope

Once validated:
- **Check every host for connections to the same destination IP/domain** — C2 infrastructure is typically shared across all compromised hosts in a campaign, so this is often the fastest way to find every other affected machine.
- **Correlate against the earlier stages of this chain** — if this host also shows LSASS access or PsExec-style lateral movement, this is one incident with a full lifecycle, not an isolated network anomaly.
- **Check DNS logs environment-wide for the same domain**, even on hosts where you haven't seen the actual connection yet — a DNS query without a completed connection can indicate blocked-but-attempted beaconing, worth knowing about even if it didn't succeed.

## 7. Containment

Priority order:
1. Block the destination IP/domain at the firewall/proxy layer immediately — this is usually the fastest way to cut the channel without needing to fully understand the implant first.
2. Network-isolate the host(s) making the connection.
3. Preserve the host for forensics before any cleanup — an active C2 implant is often the best source of information about what else the attacker did, and you lose that if you kill the process before capturing it.
4. If multiple hosts share the same C2 destination, contain all of them in the same action window — containing one at a time gives the attacker visibility into your response and time to shift infrastructure.

## 8. Recovery

- Full re-image is the standard for any host with a confirmed active C2 implant — this is not a "clean the process and move on" scenario, since you generally can't be fully confident of what else the implant did or dropped.
- Rotate credentials for anything the host had access to, consistent with the credential-dumping playbook's containment guidance — assume the C2 channel was used to move stolen credentials out, not just to receive commands.
- Confirm the blocked domain/IP stays blocked at the network layer even after hosts are cleaned, since attackers frequently attempt to re-establish contact with previously used infrastructure.

## 9. Detection improvement

- If beacon-interval analysis isn't automated (most SIEMs/XDRs can do this natively, e.g., Cortex XDR's BIOC rules or a custom Zeek/Splunk job), that's worth flagging — manual `conn.log` grepping doesn't scale past a handful of suspected hosts.
- JA3/JA3S fingerprinting for known C2 framework defaults is a high-value, low-noise detection to have in place if it isn't already, since it catches encrypted C2 traffic that content-based detection can't touch.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter action_remote_ip = "<suspect_ip>"
| fields agent_hostname, action_local_port, action_remote_port, action_total_download, action_total_upload, _time
| sort asc _time
```
(Export and analyze the `_time` deltas separately to confirm interval regularity — XQL isn't well-suited to interval math directly.)

**Microsoft Defender XDR (KQL / Advanced Hunting)**
```kql
DeviceNetworkEvents
| where RemoteIP == "<suspect_ip>" or RemoteUrl has "<suspect_domain>"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```
Checking interval regularity directly in KQL:
```kql
DeviceNetworkEvents
| where RemoteIP == "<suspect_ip>"
| order by Timestamp asc
| serialize
| extend PrevTimestamp = prev(Timestamp)
| extend DeltaSeconds = datetime_diff('second', Timestamp, PrevTimestamp)
| project Timestamp, DeltaSeconds
```

**CrowdStrike Falcon (Event Search / Falcon Query Language)**
```
event_simpleName=NetworkConnectIP4
| RemoteAddressIP4="<suspect_ip>"
| table ComputerName, LocalAddressIP4, RemoteAddressIP4, RemotePort, _time
| sort _time asc
```

**Splunk (with Zeek/Bro data)**
```spl
index=zeek sourcetype=zeek_conn dest_ip="<suspect_ip>"
| sort _time
| delta _time AS time_delta
| stats avg(time_delta) as avg_interval, stdev(time_delta) as jitter by dest_ip
```
The `stdev` relative to `avg_interval` is your jitter measure — low stdev relative to the mean is the beacon tell.

**Elastic (EQL / KQL for network data)**
```eql
network where destination.ip == "<suspect_ip>"
```
Interval analysis in Elastic is typically better done via a Timelion/Lens visualization on `@timestamp` bucketed by the connection, rather than pure EQL.

## 11. Escalation and handoff notes

When writing this up for the incident ticket:
1. Include the actual interval/jitter numbers, not just "looked regular" — a stated mean interval and standard deviation is what lets someone else independently verify the beacon call without redoing the analysis.
2. List every host and every destination found during scope, even ones only seen via DNS query without a completed connection.
3. State explicitly whether this ties to prior stages already in the ticket (credential access, lateral movement, LOLBin execution) — this playbook is usually the closing link in a chain, not a standalone finding.
4. Note the blocked indicators (IP, domain, JA3 hash) explicitly so the network/firewall team has an exact, unambiguous list to action — vague descriptions here cause the most handoff friction of any step in this chain.
