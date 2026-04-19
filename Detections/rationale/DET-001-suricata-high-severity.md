# DET‑001 — High‑Severity Suricata Exploit Attempts (Severity 1–2)

## Detection Engineering Rationale

### What This Detection Is Trying to Surface
This detection identifies confirmed exploit attempts captured by Suricata, including remote code execution, backdoor installation, and protocol abuse. Severity‑1 and severity‑2 alerts represent high‑confidence attacker behavior and provide early visibility into exploitation campaigns targeting exposed services.

### Why This Detection Exists (Thought Process)
Modern exploitation activity is dominated by automated scanners, botnets, and exploit kits. These tools generate high‑volume traffic, but only a subset of events represent actual exploit attempts. Suricata severity‑1 and severity‑2 alerts are intentionally rare and map to validated exploit signatures. Filtering for severity ≤2 ensures the detection focuses on high‑signal events that require analyst attention.

### What I Ruled Out
- Severity 3–4 alerts, which are often reconnaissance or malformed traffic.
- Generic scanning activity without exploit signatures.
- Alerts lacking confirmed exploit metadata.

The goal is to prioritize confirmed exploitation over noise, aligning with SOC triage best practices.

### Telemetry Used
- Suricata `event_type=alert`
- Signature name
- Severity
- Source and destination IPs
- Destination port
- Timestamp

### MITRE ATT&CK Mapping
- T1203 — Exploitation for Client Execution  
- T1210 — Exploitation of Remote Services

### Validation Approach
- Replayed exploit traffic to confirm signature firing.
- Verified severity extraction from Suricata logs.
- Correlated exploit attempts with Cowrie to ensure no session creation occurred.
- Confirmed low false‑positive rate.

### False Positives Considered
Minimal. Severity‑1 alerts are designed to be high‑confidence and rarely misfire.

### Detection Improvements
- Add correlation with Cowrie session creation.
- Add ASN‑based risk scoring.
- Add exploit burst thresholding to identify coordinated campaigns.

