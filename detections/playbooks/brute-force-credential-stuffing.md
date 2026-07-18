# Playbook: Brute Force & Credential Stuffing Detection

**MITRE ATT&CK:** T1110 (Brute Force), T1110.003 (Password Spraying), T1110.004 (Credential Stuffing)

**Where this sits in the framework:** this is an alternate entry point alongside phishing — instead of tricking a user into giving up access, the attacker tries to guess or reuse credentials directly against exposed authentication endpoints. It's one of the highest-volume, lowest-sophistication attack types you'll see in a real SOC queue, and precisely because of that volume, getting the triage fast and accurate matters more here than almost anywhere else in this repo.

---

## 1. What the detection actually looks like

Three distinct sub-patterns, each with a different signature — conflating them leads to weak triage:

- **Classic brute force**: many failed login attempts against **one account** from one or a few sources, in rapid succession
- **Password spraying**: a **few** attempts against **many accounts**, spaced out to avoid per-account lockout thresholds — this is deliberately designed to look quiet on a per-account basis and only becomes visible when viewed in aggregate across the environment
- **Credential stuffing**: login attempts using **previously breached username/password pairs** (from unrelated third-party breaches) against your environment, often distinguishable by a higher success rate on first attempt than random guessing would produce, and typically coming from distributed IPs/infrastructure rather than one source

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Windows Security Event 4625 | Failed logon attempts — account name, source IP, logon type |
| Windows Security Event 4624 | Successful logons — critical for confirming whether an attempt eventually succeeded |
| Entra ID / Okta sign-in logs | Cloud identity provider view, often includes risk scoring and impossible-travel flags natively |
| VPN/firewall authentication logs | Source IP reputation and geolocation for external-facing authentication attempts |
| Application/API authentication logs | For credential stuffing against web apps rather than Windows/AD directly |

## 3. Triage: is this worth escalating?

Ask, in order, and note the questions differ meaningfully by sub-pattern:

1. **Which pattern is this** — one account/many attempts, many accounts/few attempts each, or a stuffing pattern using known-breached pairs? Identify this first since it changes every subsequent question.
2. **Did any attempt succeed?** This is the single most important gate in the entire playbook — an unsuccessful brute force attempt, however large, is a much lower-urgency finding than even one successful login following a spray/stuffing pattern.
3. **Is the source IP/infrastructure associated with known attack tooling or a VPN/proxy exit node** commonly used to mask credential stuffing traffic? Threat intel reputation on the source matters more here than in almost any other playbook.
4. **For password spraying specifically**: is the attempt volume per account low enough that it wouldn't trip a standard lockout policy? If the pattern is deliberately staying under known thresholds, that's itself a strong indicator of sophistication and intent, not just noise.

Any confirmed successful login following a brute force, spray, or stuffing pattern escalates immediately regardless of volume — a single successful credential-stuffing hit matters more than ten thousand failed spray attempts.

## 4. Investigation: distinguishing noise from a real hit

You're answering: *did this pattern actually produce unauthorized access, and if so, to which account(s).*

**Classic brute force** — look for:
```
Event 4625 x many, same TargetUserName, same or few Source IPs, tight time clustering
  → followed by Event 4624 (success) on the same account = confirmed compromise
```

**Password spraying** — look for:
```
Event 4625 x few per account, but across MANY different TargetUserName values, same time window, same source infrastructure
  → this pattern is invisible if you only look at one account's failure count; it requires aggregating across the environment
```

**Credential stuffing** — look for:
```
Login attempts using usernames formatted as external email addresses (not matching internal AD naming conventions)
  → distributed source IPs (often residential proxy networks specifically built to evade IP-based rate limiting)
  → unusually high first-attempt success rate compared to what random guessing would produce
```

Details that matter:
- **Timing regularity**: spray attacks often show suspiciously regular spacing between attempts (deliberately staying under lockout thresholds) — similar to the C2 beaconing interval concept, but applied to authentication attempts instead of network connections
- **Geographic/IP diversity**: credential stuffing infrastructure is frequently distributed specifically to avoid single-IP-based detection, where classic brute force is often concentrated from very few sources

## 5. Threat validation

Confirm true positive requiring full incident response if:
- Any attempt succeeded, regardless of the volume of preceding failures
- Success is associated with an account that then shows anomalous behavior afterward (new device registration, impossible travel, immediate privilege enumeration — connects directly into the recon-discovery playbook)

Lower-priority (block and monitor, not full incident) if:
- All attempts failed and source IP/infrastructure has been blocked
- Pattern is confirmed noise (e.g., a misconfigured service account retrying with an expired credential — common false-positive source for classic brute force alerts specifically)

## 6. Scope

Once a successful login is confirmed:
- **Check every account targeted by the same source infrastructure** — spray and stuffing attacks are rarely aimed at just one account; find every account that was attempted, not just the one that succeeded.
- **Check what the compromised account did after login** — this connects directly forward into the reconnaissance/discovery playbook (did they immediately start enumerating?) and potentially credential dumping or lateral movement from there.
- **Check whether MFA was bypassed, not configured, or fatigued** (MFA push-bombing is a related and increasingly common technique) — this materially changes what containment and hardening steps are needed.

## 7. Containment

Priority order:
1. Disable or force password reset on any account with a confirmed successful login from the malicious pattern.
2. Revoke active sessions/tokens for that account — a password reset alone doesn't invalidate an already-active session.
3. Block the source IP/infrastructure at the authentication layer (VPN, firewall, identity provider conditional access policy).
4. If this connects forward into confirmed post-login activity (recon, lateral movement), contain per those playbooks as well — this is rarely the end of the incident once a login succeeds.

## 8. Recovery

- Force password resets for any account confirmed compromised, and consider a broader reset if the same password policy weakness (short passwords, no complexity requirement) likely affects other accounts similarly.
- If MFA wasn't enforced on the compromised account, this is the point to close that gap specifically, not just for this account but any others without it.

## 9. Detection improvement

- If password spraying detection relies only on per-account failure thresholds (not aggregated across accounts), that's the single most common detection gap in this category — spraying is specifically designed to defeat per-account thresholds and requires environment-wide aggregation to catch.
- Conditional access policies that factor in impossible travel, unfamiliar device, and source IP reputation (available natively in most modern identity providers) are worth confirming are actually enabled and enforced, not just available.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.AUTHENTICATION and action_logon_result = "FAILURE"
| comp count() as fail_count by actor_effective_username, source_ip
| filter fail_count > 10
```
Spray pattern (many accounts, same source):
```
dataset = xdr_data
| filter event_type = ENUM.AUTHENTICATION and action_logon_result = "FAILURE"
| comp count(distinct actor_effective_username) as unique_accounts by source_ip
| filter unique_accounts > 20
```

**Microsoft Defender XDR / Entra ID (KQL)**
```kql
SigninLogs
| where ResultType != 0  // failed sign-ins
| summarize FailCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailCount > 10
```
Password spray detection (many accounts, same source, low per-account count):
```kql
SigninLogs
| where ResultType != 0
| summarize UniqueAccounts = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where UniqueAccounts > 20
```

**CrowdStrike Falcon (Identity Protection module)**
```
event_simpleName=AuthActivityAudit
| stats count as attempts by UserName, SourceIP
| where attempts > 10
```

**Splunk**
```spl
index=main EventCode=4625
| stats count as fail_count by TargetUserName, IpAddress
| where fail_count > 10
```
Spray pattern:
```spl
index=main EventCode=4625
| stats dc(TargetUserName) as unique_accounts by IpAddress
| where unique_accounts > 20
```

**Elastic**
```eql
sequence by source.ip with maxspan=1h
  [authentication where event.outcome == "failure"] with runs=10
```

## 11. Escalation and handoff notes

When writing this up:
1. State clearly which sub-pattern this is (brute force, spray, or stuffing) — the response and hardening recommendations differ meaningfully between them.
2. State explicitly whether any attempt succeeded — this is the single fact that determines whether this is a blocked-and-monitored event or a full incident.
3. If a login succeeded, reference the reconnaissance/discovery and lateral movement playbooks for what to check next — a successful credential-based entry rarely stays isolated to the login event itself.
4. Note MFA status on the affected account(s) explicitly, since it's directly relevant to both the current finding and the hardening recommendation.
