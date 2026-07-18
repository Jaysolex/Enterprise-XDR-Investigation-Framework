# Playbook: Phishing & Initial Access

**MITRE ATT&CK:** T1566 (Phishing), T1204 (User Execution), T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)

**Where this sits in the chain:** this is the front bookend. Everything in credential dumping, lateral movement, LOLBin execution, and C2 beaconing typically starts here — a user opens something they shouldn't have. Getting this stage right is higher leverage than any other stage, because a contained phishing incident never generates the other four.

---

## 1. What the detection actually looks like

- Email gateway/secure email gateway (SEG) flags: sender domain lookalike, newly registered sending domain, failed SPF/DKIM/DMARC, known malicious attachment hash or URL
- A user reports a suspicious email (still one of the highest-value detection sources — never deprioritize user reports in favor of automated tooling)
- Endpoint telemetry: an Office application (`winword.exe`, `excel.exe`, `outlook.exe`) spawning a child process it normally never spawns (`cmd.exe`, `powershell.exe`, `mshta.exe`) — this is the single strongest phishing-to-execution indicator available on the endpoint
- A macro-enabled document (`.docm`, `.xlsm`) opened shortly before unusual process activity
- A user navigating to a credential-harvesting page shortly after clicking a link — often visible via proxy/DNS logs showing a newly registered domain mimicking a known brand or SSO portal

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Email gateway/SEG logs | Sender, SPF/DKIM/DMARC results, attachment hash, embedded URLs, delivery/quarantine status |
| Sysmon Event ID 1 | Process creation — the Office-app-spawns-shell pattern is captured here |
| Sysmon Event ID 7 | Module/DLL loads — macro execution often loads specific scripting DLLs |
| Proxy/web logs | Whether the user actually clicked through, what domain they reached, whether credentials were submitted |
| DNS logs | Query for the phishing domain even if the connection was blocked downstream |
| Mailbox audit logs (M365/Exchange) | Whether the email was forwarded, replied to, or if mailbox rules were created afterward (sign of a successful credential-phish leading to mailbox takeover) |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Was the email delivered, or already quarantined/blocked by the gateway?** If blocked pre-delivery, this is a lower-urgency item — log it, but no user interaction occurred.
2. **Did the user open the attachment or click the link?** Check proxy/endpoint logs for user interaction, don't assume based on the email alone.
3. **If a document was opened, did an Office process spawn a shell or scripting engine afterward?** This is the highest-signal question in the entire playbook — this single pattern (Office app → cmd/powershell/mshta) turns a "someone got an email" report into a confirmed execution incident.
4. **If a link was clicked, did the user reach a credential-harvesting page, and did they submit anything?** Check proxy logs for POST requests to the destination, which is a stronger indicator than simply visiting the page.

If step 3 or step 4 confirms actual user interaction with malicious content (not just delivery), escalate to full investigation.

## 4. Investigation: confirming execution or credential submission

**Attachment-based path** — the process tree that matters most in this entire playbook:
```
winword.exe (or excel.exe, outlook.exe)
  └── cmd.exe /c powershell.exe -enc <base64>      ← Office spawning a shell is almost never legitimate
        └── (continues into the PowerShell/LOLBin playbook from here)
```
If you see this pattern, you're no longer investigating "did a phishing email get opened" — you're now in the PowerShell/LOLBin playbook for the next stage, and should treat this as one continuous incident.

**Link-based / credential harvesting path:**
- Confirm the destination domain age and hosting reputation (very recently registered domains mimicking Microsoft/Okta/Google login pages are the dominant pattern)
- Check proxy logs for a completed POST request to the domain (indicates credentials were actually typed and submitted, not just that the page loaded)
- If credentials were submitted, immediately check for anomalous sign-in activity on that account — impossible travel, new device registration, mailbox rule creation — since the attacker may already be using the harvested credential

## 5. Threat validation

Confirm true positive (requiring response, not just logging) if:
- User opened an attachment AND an Office process spawned a shell/scripting engine afterward, OR
- User clicked a link AND reached a confirmed credential-harvesting page AND a form submission occurred, OR
- Sender/domain/attachment matches a known threat intelligence indicator regardless of user interaction (still worth blocking fleet-wide even if this specific user didn't fall for it)

Lower-priority (log, don't fully investigate) if:
- Email was quarantined pre-delivery with no user interaction
- User reported the email without opening/clicking (this is the ideal outcome — a false positive at investigation level, but a true positive for security awareness working as intended)

## 6. Scope

Once validated:
- **Search the entire mail environment for the same sender, subject, or attachment hash** — phishing is rarely sent to one person; find every recipient, not just the one who reported it or triggered the alert.
- **Check the specific mailbox for post-compromise indicators** if credentials were submitted — new mailbox forwarding rules, new inbox rules that move/delete messages (attackers often set up rules to hide replies from IT/security), OAuth app consents granted around the same time.
- **If execution occurred on the endpoint,** this connects forward into whichever of the other three playbooks matches what you find — treat as one incident with a phishing origin, not a separate case.

## 7. Containment

Priority order:
1. Purge the email from all mailboxes it was delivered to (most email platforms support a bulk remediation/purge action once you have the message ID or hash).
2. Block the sending domain and any linked URLs at the email gateway and web proxy.
3. If credentials were submitted: force a password reset immediately and revoke active sessions/tokens for that account — a reset alone doesn't invalidate an already-active session token.
4. If execution occurred on the endpoint: isolate that host and proceed into containment steps from whichever downstream playbook applies (credential dumping, lateral movement, etc.).

## 8. Recovery

- Restore any mailbox rules or forwarding settings the attacker may have changed back to the user's original configuration.
- Revoke and reissue any OAuth app consents granted during the compromise window.
- If endpoint execution occurred, recovery follows whichever downstream playbook's recovery steps apply.

## 9. Detection improvement

- If the Office-app-spawns-shell detection isn't already a standalone high-fidelity rule (rather than bundled into generic "suspicious process" alerting), that's worth flagging — it's one of the cleanest, lowest-false-positive detections available in this entire chain.
- If user-reported phishing doesn't have a fast, low-friction reporting button/workflow, that's worth flagging to whoever owns security awareness — the fastest phishing detections in most real environments come from users, not tooling, and friction in reporting directly costs detection speed.

## 10. XDR/EDR query reference

**Cortex XDR (XQL)**
```
dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter causality_actor_process_image_name in ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
| filter action_process_image_name in ("cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| fields agent_hostname, actor_effective_username, causality_actor_process_image_name, action_process_image_name, action_process_image_command_line, _time
```

**Microsoft Defender XDR (KQL / Advanced Hunting)**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```
Mailbox rule creation following a suspected credential phish:
```kql
CloudAppEvents
| where ActionType == "New-InboxRule" or ActionType == "Set-Mailbox"
| where Timestamp > datetime(<incident_start>)
| project Timestamp, AccountId, ActionType, RawEventData
```

**CrowdStrike Falcon (Event Search / Falcon Query Language)**
```
event_simpleName=ProcessRollup2
| ParentBaseFileName IN (winword.exe, excel.exe, outlook.exe, powerpnt.exe)
| FileName IN (cmd.exe, powershell.exe, mshta.exe, wscript.exe, cscript.exe)
| table ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, _time
```

**Splunk (Sysmon + email gateway data)**
```spl
index=main EventCode=1 ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*outlook.exe"
| search Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*mshta.exe"
| table _time, ComputerName, User, ParentImage, Image, CommandLine
```

**Elastic (EQL)**
```eql
process where event.type == "start" and
  process.parent.name in ("winword.exe", "excel.exe", "outlook.exe") and
  process.name in ("cmd.exe", "powershell.exe", "mshta.exe")
```

## 11. Escalation and handoff notes

When writing this up for the incident ticket:
1. State clearly whether this was delivery-only, opened-but-no-execution, or confirmed execution/credential submission — these three outcomes require completely different response urgency and should never be conflated in a ticket summary.
2. Include the full recipient list found during scope, not just the reporting user.
3. If credentials were submitted, explicitly document whether the account's active sessions were revoked (not just password reset) — this is a commonly missed step that leaves a compromised session valid even after remediation.
4. If this incident connects forward into execution/lateral movement/C2, reference those tickets explicitly rather than treating this as closed in isolation.
