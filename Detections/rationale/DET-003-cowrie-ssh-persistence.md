# DET‑002 — Suricata Malware File Transfer (Executable / Script Payloads)

## Detection Engineering Rationale

### What This Detection Is Trying to Surface
This detection identifies executable, script, or binary payloads transferred over the network. These payloads often represent malware staging, botnet installation, or tooling delivery following initial access.

### Why This Detection Exists (Thought Process)
Suricata’s `fileinfo` events provide detailed metadata about transferred files, including MD5 hashes, magic file types, and filenames. Filtering for executable or script‑type payloads isolates high‑risk transfers with minimal noise. This aligns with industry practices for detecting ingress tool transfer and malware staging.

### What I Ruled Out
- Non‑executable file types such as images, HTML, or text.
- Partial or incomplete downloads.
- Benign file transfers, which are rare in honeypot environments.

The focus remains on payloads that can execute or stage malicious activity.

### Telemetry Used
- Suricata `event_type=fileinfo`
- MD5 hash
- Magic type
- Filename
- Source and destination IPs
- File size
- Timestamp

### MITRE ATT&CK Mapping
- T1105 — Ingress Tool Transfer

### Validation Approach
- Verified MD5 extraction and matching against malware sandboxes.
- Correlated Suricata fileinfo events with Cowrie download commands.
- Identified repeated payload distribution patterns.

### False Positives Considered
Low. Honeypot file transfers are almost always malicious.

### Detection Improvements
- Add correlation with Cowrie command input.
- Add repeated‑hash alerting across multiple days.
- Add URL and domain reputation scoring.

