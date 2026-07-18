# Incident Report Template

A standard structure for writing up any investigation from this framework once it's been worked through a playbook. Copy this template per incident — the goal is that someone who wasn't involved (a manager, an auditor, a handoff to another analyst) can fully understand what happened and what was done from this document alone.

---

## Incident Summary

**Incident ID:**
**Date/time detected:**
**Date/time closed:**
**Analyst(s):**
**Severity:** (Critical / High / Medium / Low)
**Playbook(s) referenced:** (e.g., Credential Dumping → Lateral Movement)
**Status:** (Open / Contained / Closed / Monitoring)

**One-paragraph summary** (written for a non-technical reader — what happened, what was done, what the outcome was):

---

## Detection

**What triggered the alert:**
(Name the specific telemetry/rule — e.g., "Sysmon Event 10, GrantedAccess 0x1410 against lsass.exe" — not just "XDR flagged it.")

**Detection source/platform:**

**Initial alert timestamp:**

---

## Triage

**Questions asked and answers found:**
(List the specific triage questions from the relevant playbook and what you found for each — this is what makes the eventual validation call defensible later.)

1.
2.
3.

---

## Investigation

**Process tree / command sequence observed:**
```
(paste the annotated tree or sequence here)
```

**Key telemetry reviewed:**
(List sources checked — Sysmon IDs, specific logs, query platforms used)

**Decoded/reconstructed content** (if applicable — e.g., decoded PowerShell, extracted archive contents):

---

## Validation

**True positive / false positive determination:**

**Criteria met** (reference the specific validation criteria from the playbook):

---

## Scope

**Hosts affected:**

**Accounts affected:**

**Data affected** (if applicable — be as specific as possible; vague scoping creates downstream legal/compliance problems):

**Related incidents/tickets this connects to** (upstream or downstream in the attack chain):

---

## Containment

**Actions taken, in order, with timestamps:**

1.
2.
3.

**Who authorized each action** (relevant especially for insider threat cases, per that playbook's guidance):

---

## Recovery

**Remediation steps taken:**

**Verification that remediation was effective** (don't just state an action was taken — confirm the resulting state):

**Credentials/keys rotated:**

---

## Detection Improvement

**Gaps identified:**

**Rules/detections created or tuned as a result:**

**Ticket/tracking reference for any follow-up work:**

---

## Legal/Compliance Notes (if applicable)

**Data with notification obligations confirmed exposed:** (Yes/No — if yes, note who was notified and when)

**HR/Legal involvement** (for insider threat cases specifically):

---

## Timeline (optional, for complex/multi-stage incidents)

| Timestamp | Event |
|---|---|
| | |
| | |

