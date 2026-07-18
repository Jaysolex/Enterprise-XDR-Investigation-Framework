# Network Telemetry Reference

Background on the network-layer data sources used most directly in the C2 beaconing and data exfiltration playbooks — the telemetry that sits outside any single host and captures what's actually crossing the wire.

## Zeek (formerly Bro)

The foundation for most of the network analysis referenced elsewhere in this repo — a passive network traffic analyzer that produces structured, queryable logs rather than raw packet captures.

Key logs used across playbooks:

| Log | Contents | Used in |
|---|---|---|
| `conn.log` | Every connection: duration, byte counts (orig/resp), ports | C2 beaconing (interval analysis), data exfiltration (volume analysis) |
| `dns.log` | Every DNS query and response | C2 beaconing (DGA detection), data exfiltration (tunneling detection) |
| `ssl.log` / `x509.log` | TLS handshake details, certificate metadata | C2 beaconing (certificate age/self-signed detection) |
| `http.log` | HTTP request/response metadata (not full content by default) | Supplementary to the above where traffic isn't encrypted |

Zeek's `conn.log` is the backbone of the beacon-interval math shown in the C2 playbook — because it logs `ts` (timestamp) for every connection, interval and jitter can be computed directly without needing full packet capture.

## Suricata / other IDS (Intrusion Detection Systems)

Signature-based detection — matches traffic against known-bad patterns (specific byte sequences, JA3/JA3S fingerprints associated with known C2 frameworks, known malicious domains). Complements Zeek rather than replacing it: Zeek gives you the queryable connection metadata to investigate *after* something looks suspicious; Suricata gives you the initial signature match that says something looks suspicious in the first place.

## JA3 / JA3S fingerprinting

A specific technique worth understanding on its own: fingerprints the *way* a TLS client and server negotiate a handshake (cipher suites offered, extensions, in a specific order) rather than the certificate or domain itself. This matters because it can identify known C2 frameworks (Cobalt Strike, Sliver, Metasploit default profiles) even when the traffic is fully encrypted and the domain/IP is unknown or freshly rotated — referenced directly in the C2 beaconing playbook as a detection that works even without visibility into the actual payload.

## NetFlow / firewall connection logs

Lower fidelity than Zeek (typically just source/destination/port/byte-count, no protocol-level parsing) but often available at much larger scale across an entire network without needing a dedicated sensor at every point — useful for the data-exfiltration playbook's "check every host for connections to the same destination" scoping step, where breadth matters more than depth.

## DNS tunneling — why it gets special attention

Referenced in the data-exfiltration playbook specifically because DNS is one of the most reliably-allowed outbound protocols in almost any network (blocking it breaks normal internet use), which makes it an attractive channel for encoding stolen data into query names. Detection here relies on statistical properties of the queries themselves — unusually long subdomain labels, high query volume to a single domain, high entropy (randomness) in subdomain content — rather than blocking DNS outright, which isn't a realistic option in most environments.
