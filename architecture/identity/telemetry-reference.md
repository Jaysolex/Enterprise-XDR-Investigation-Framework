# Identity Telemetry Reference

Background on identity-layer telemetry — the data sources that sit above individual hosts and cover authentication, authorization, and account behavior across the environment. Directly relevant to the brute-force/credential-stuffing, insider threat, and credential-dumping playbooks.

## Active Directory / Kerberos

- **Kerberoasting** (not yet a dedicated playbook in this repo, but a common real-world technique worth knowing): requesting service tickets for accounts with Service Principal Names (SPNs) set, then attempting offline cracking of the ticket's encrypted portion — detectable via Event ID 4769 (Kerberos service ticket request) with an unusual encryption type (RC4 rather than AES) or unusual request volume from one account
- **Golden/Silver ticket attacks**: forging Kerberos tickets using a compromised KRBTGT (golden) or service account (silver) hash — referenced in the credential-dumping playbook's escalation notes as a reason LSASS access on a domain controller is materially more severe than on a workstation
- **NTLM relay/abuse**: NTLM authentication, being challenge-response based, is vulnerable to relay attacks where a captured authentication attempt is forwarded to a different target — increasingly mitigated by SMB signing and Extended Protection for Authentication, worth confirming are enabled

## Entra ID (Azure AD) / cloud identity sign-in logs

Far richer out of the box than on-premises AD logging, because the identity provider itself computes risk signals:

- **Risky sign-in detection**: impossible travel, unfamiliar sign-in properties, anonymous IP address, atypical travel — all computed natively and available without custom correlation logic, directly relevant to the brute-force/credential-stuffing playbook
- **Conditional Access logs**: show not just whether a sign-in succeeded, but which policy evaluated it and why (MFA required and satisfied, MFA required and not satisfied, blocked by location policy, etc.)
- **Audit logs** (distinct from sign-in logs): capture directory changes — new app registrations, role assignments, mailbox rule creation — directly relevant to the phishing playbook's post-compromise mailbox-takeover indicators

## Okta / other third-party identity providers

Similar conceptual coverage to Entra ID — sign-in events, MFA challenge results, and (for Okta specifically) ThreatInsight for known-bad IP reputation built into sign-in risk scoring. Field names differ from Microsoft's schema but the underlying signals (risk score, MFA result, device trust) map to the same concepts referenced in the query examples throughout this repo's playbooks.

## Why identity telemetry is treated separately from host telemetry in this repo

Host-based playbooks (lateral movement, credential dumping, LOLBins) answer "what did a process do." Identity telemetry answers a different question — "was this authentication event itself legitimate" — and the two need to be correlated together, not substituted for each other. A successful login (identity layer) followed by unusual process activity (host layer) is a stronger finding than either signal alone, which is why the brute-force playbook explicitly hands off into the reconnaissance/discovery playbook once a login succeeds.
