# Containment Procedures

Generic, platform-by-platform containment actions referenced across this repo's playbooks. Each playbook's own containment section states *when* to take these actions and in what priority order for that specific technique — this file is the *how*, consolidated once instead of repeated in every playbook.

## Host isolation

**Cortex XDR**: Endpoints → select host → Isolate. Preserves the agent's ability to still communicate with the Cortex management console while blocking all other network traffic — this is the key difference from a network-layer block, since it keeps you able to continue investigating/pulling telemetry from an isolated host.

**CrowdStrike Falcon**: Host Management → select host → Network Contain. Same principle — maintains the sensor's connection to the Falcon cloud while blocking everything else.

**Microsoft Defender XDR**: Device inventory → select device → Isolate device. Offers "Full isolation" or "Selective isolation" (the latter allows specific outbound processes to continue, useful if you need a specific business application to keep functioning during investigation).

**Why EDR-based isolation over physically disconnecting the host**: physical disconnection (unplugging, disabling the NIC) loses the agent's ability to continue collecting telemety and doesn't preserve volatile memory state the way EDR-level network isolation does. Always prefer the agent-based isolation method referenced above unless the EDR agent itself is confirmed compromised or unresponsive.

## Account containment

**Disable vs. reset vs. session revocation — these are three different actions and incidents often need more than one:**

- **Disable the account**: prevents new logins, but doesn't invalidate an already-active session/token
- **Reset the password**: forces a new credential, but again doesn't invalidate existing active sessions in most identity providers
- **Revoke active sessions/tokens**: the step that actually terminates a currently-active login — in Entra ID, this is `Revoke-AzureADUserAllRefreshToken` (or the equivalent action in the Entra admin portal); in Okta, "Clear sessions" under the user's security tab

For any incident involving a confirmed compromised account, do all three, not just the password reset — this is referenced explicitly in the phishing, brute-force, and credential-dumping playbooks as a commonly missed step.

## Network-layer blocking

**Firewall/proxy**: block destination IP/domain at the perimeter — fastest way to cut an active C2 channel or exfiltration destination, referenced in the C2 beaconing and data exfiltration playbooks as the first containment action specifically because it can be done before host-level isolation is even complete.

**DNS sinkholing**: redirecting a malicious domain's resolution to an internal, non-routable address — useful when you want to prevent connection without fully blocking DNS resolution itself (which can sometimes tip off more sophisticated malware that it's being contained).

## Credential/key rotation

Referenced across credential-dumping, lateral-movement, phishing, and cloud-misconfiguration playbooks: any credential that could plausibly have been exposed should be rotated, not just the one confirmed used maliciously. Under-scoping this (rotating only the specific account seen in an alert, rather than everything that shares the compromised host/session/blast-radius) is called out repeatedly across playbooks as the most common reason incidents reopen after apparent closure.

## Coordinated (multi-host) containment

Referenced specifically in the ransomware and data-exfiltration playbooks: when multiple hosts share the same indicator (same C2 destination, same encryption pattern), contain all of them in the same action window rather than sequentially. Sequential containment gives an adaptive attacker or a still-spreading ransomware payload time to react before you've finished.

## When containment precedes full validation (the ransomware exception)

Every other playbook in this repo validates before containing. Ransomware is the deliberate exception — containment (isolation) begins the moment mass encryption or shadow-copy deletion is observed, running in parallel with the remaining investigation rather than waiting for it. This is called out explicitly in the ransomware playbook and is the one place in this repo where the standard triage-then-contain sequence is intentionally reversed.
