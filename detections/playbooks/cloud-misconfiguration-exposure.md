# Playbook: Cloud Misconfiguration Exposure

**MITRE ATT&CK:** T1530 (Data from Cloud Storage), T1580 (Cloud Infrastructure Discovery), T1078.004 (Valid Accounts: Cloud Accounts)

**Where this sits in the framework:** this is the one playbook in the repo where there's often no "attacker" telemetry at all — the exposure exists because of how something was configured, not because someone broke in. Detecting this is closer to continuous auditing than incident response, and it's included specifically because it's a distinct skill from every technique-based playbook above it: you're hunting for a condition, not a sequence of malicious actions.

---

## 1. What the detection actually looks like

Unlike every prior playbook, there's frequently no "alert" in the traditional sense until either a scanner flags the condition or someone external finds it first (worst case). What you're looking for:

- Publicly readable/writable cloud storage buckets (S3, Azure Blob, GCS) that should be private
- Overly permissive IAM roles/policies — wildcard resource or action permissions (`"Action": "*"`, `"Resource": "*"`) where scoped permissions would suffice
- Security groups/network ACLs with overly broad inbound rules (`0.0.0.0/0` on sensitive ports like RDP/SSH/database ports)
- Exposed management interfaces (cloud console, Kubernetes API, database admin panels) reachable from the public internet without additional access controls
- Unencrypted data at rest where encryption should be enforced by policy
- Default or unrotated credentials/access keys, especially long-lived static keys where short-lived tokens would be appropriate

## 2. Telemetry sources to pull

| Source | What it gives you |
|---|---|
| Cloud provider's native posture tool (AWS Security Hub / Config, Azure Defender for Cloud, GCP Security Command Center) | Automated, continuous configuration assessment against best-practice baselines |
| CSPM (Cloud Security Posture Management) tooling if deployed separately | Cross-cloud visibility if the environment spans multiple providers |
| IAM policy analyzers (AWS IAM Access Analyzer, similar tools) | Flags policies granting more access than is actually used |
| CloudTrail / Azure Activity Log / GCP Audit Logs | Confirms whether an exposed resource was actually accessed externally, not just theoretically exposed |
| Public internet scanning services (Shodan, Censys) | External view of what's actually reachable — useful for validating that internal assessment matches external reality |

## 3. Triage: is this worth escalating?

Ask, in order:

1. **Is the exposed resource actually reachable, or does it just look permissive on paper?** A security group allowing `0.0.0.0/0` on a port with no service actually listening is a lower-urgency finding than the same rule on a port serving a live database.
2. **Does the resource contain or provide access to sensitive data**, or is it something low-value (a static website's public assets bucket, correctly public by design)? Not every public-facing resource is a misconfiguration — some are intentional and correct.
3. **Has the exposure already been accessed externally?** Check access logs for the resource — an exposure with confirmed unexpected external access is a different urgency tier than a theoretical exposure caught by a scanner before anyone found it.
4. **How long has this been exposed?** A newly introduced misconfiguration (e.g., from a recent deployment) versus a long-standing one changes the likely scope of who may have already found it.

If the resource is genuinely reachable, contains sensitive data, and shows any sign of unexpected external access in the logs, escalate to full investigation immediately — this is functionally now a suspected breach, not just a configuration finding.

## 4. Investigation: confirming exposure and access

You're answering: *what is actually exposed, is it sensitive, and has anyone outside the organization touched it.*

**Checking a suspect S3 bucket's actual public accessibility (AWS CLI, read-only):**
```bash
aws s3api get-bucket-policy-status --bucket <bucket-name>
aws s3api get-public-access-block --bucket <bucket-name>
```
A `PolicyStatus.IsPublic: true` combined with public access block settings that don't restrict it confirms actual (not just theoretical) public exposure.

**Checking access logs for external requests to a suspect resource:**
```bash
aws s3api get-bucket-logging --bucket <bucket-name>
# then review the target logging bucket for requester IPs outside known corporate ranges
```

Details that matter:
- **Distinguish "technically public" from "actually accessed"**: a bucket can be misconfigured for a long time with zero external access if no one found it — this matters for prioritization, though it doesn't make the misconfiguration acceptable to leave unfixed
- **Check for automated scanner traffic in the access logs** even if you don't find targeted human access — internet-wide scanning services find newly exposed resources within hours in many cases, so "no external access yet" has a shrinking shelf life
- **IAM policy blast radius**: for overly permissive IAM roles, check what that role has actually been used to do (via CloudTrail), not just what it's theoretically capable of — actual usage tells you the realistic risk, theoretical permission tells you the ceiling

## 5. Threat validation

This playbook validates differently from the technique-based ones — there's rarely a "false positive" on whether the misconfiguration exists (the scanner is usually right), but there is a meaningful validation question on **severity**:

- **Confirmed high severity**: sensitive data reachable publicly, with evidence of external access in logs
- **Confirmed misconfiguration, lower immediate severity**: exposure exists but no sensitive data present, or no external access evidence yet — still needs remediation, but not incident-response urgency
- **Not actually a misconfiguration**: resource is intentionally public (a CDN asset bucket, a public documentation site) — verify against architecture documentation before treating as a finding

## 6. Scope

Once confirmed as a genuine, sensitive exposure:
- **Check for the same misconfiguration pattern across other resources** — misconfigurations are frequently systemic (a bad Terraform module, a permissive default in an infrastructure-as-code template) rather than a one-off, so finding one is a strong reason to check for siblings.
- **Check IAM policies attached to the exposed resource** for what else that role/credential could reach, since cloud misconfigurations often chain — an exposed bucket might also reveal credentials that unlock further access elsewhere.
- **Cross-reference with the data-exfiltration playbook's indicators** if external access is confirmed — at that point this is functionally a breach investigation, not a configuration review.

## 7. Containment

Priority order:
1. Restrict public access immediately (`aws s3api put-public-access-block` or provider equivalent) — this is usually a fast, low-risk action that doesn't require extensive change-control given the exposure risk.
2. Rotate any credentials or access keys that may have been exposed alongside the misconfigured resource.
3. Tighten IAM policies to least-privilege scoping rather than wildcard permissions.
4. If external access was confirmed, treat as a breach from this point forward and follow the data-exfiltration playbook's scope/containment guidance in parallel.

## 8. Recovery

- Recovery is primarily configuration remediation rather than host cleanup — apply the corrected access policy, verify via the same check used in investigation that it's now actually restricted, not just changed.
- If the misconfiguration originated from an infrastructure-as-code template or default, fix the source template, not just the individual resource — otherwise the same misconfiguration reappears on the next deployment.

## 9. Detection improvement

- If continuous configuration scanning (CSPM or the cloud provider's native posture tool) isn't already running and alerting automatically, that's the foundational gap — this entire category of finding is far better caught by continuous automated scanning than by manual review or waiting for an external report.
- Consider whether infrastructure-as-code templates have policy-as-code checks (e.g., blocking a Terraform plan that would create a public-by-default bucket) built into the deployment pipeline itself — this prevents the misconfiguration from being deployed in the first place, which is more effective than catching it after the fact every time.

## 10. XDR/EDR / cloud posture query reference

**AWS (CLI / Security Hub)**
```bash
# List all S3 buckets with public access
aws s3api list-buckets --query 'Buckets[].Name' --output text | \
  xargs -I {} aws s3api get-public-access-block --bucket {}
```
Security Hub finding query (via CLI):
```bash
aws securityhub get-findings --filters '{"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}]}'
```

**Azure (Defender for Cloud / KQL via Resource Graph)**
```kql
Resources
| where type =~ "microsoft.storage/storageaccounts"
| where properties.allowBlobPublicAccess == true
| project name, resourceGroup, subscriptionId
```

**GCP (Security Command Center)**
```bash
gcloud scc findings list <organization-id> \
  --filter="category=\"PUBLIC_BUCKET_ACL\""
```

**Cross-cloud (if using a CSPM tool with a query interface, conceptually)**
```
resource.type = "storage_bucket"
AND public_access = true
AND contains_sensitive_data = true
```

## 11. Escalation and handoff notes

When writing this up:
1. State the exposure window if determinable (when it was likely introduced, based on IaC deployment history or config change logs) — this matters for realistically scoping who may have found it.
2. State explicitly whether external access was confirmed in logs or not — this is the single fact that determines whether this stays a configuration-remediation ticket or escalates to a breach investigation.
3. If the misconfiguration traces back to a shared template or default, flag that specifically for the platform/infrastructure team, not just the individual resource owner — fixing one instance without fixing the source guarantees recurrence.
4. Note the remediation verification step explicitly (re-checked and confirmed restricted) — a ticket that says a fix was "applied" without confirmation of the resulting state is incomplete.
