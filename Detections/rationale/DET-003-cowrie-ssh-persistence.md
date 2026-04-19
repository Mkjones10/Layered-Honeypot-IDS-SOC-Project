# DET‑003 — Cowrie SSH Key Injection and Persistence Attempts

## Detection Engineering Rationale

### What This Detection Is Trying to Surface
This detection identifies hands‑on‑keyboard persistence attempts inside the Cowrie honeypot. These include SSH key injection, .ssh directory manipulation, and file attribute modification. These behaviors indicate that an attacker has moved beyond brute force and is attempting to establish long‑term access.

### Why This Detection Exists (Thought Process)
Attackers who successfully authenticate often follow a predictable persistence sequence:
1. Delete the existing `.ssh` directory.
2. Recreate `.ssh`.
3. Inject their own public key into `authorized_keys`.
4. Modify file attributes to prevent removal.

This sequence is a strong indicator of persistence and aligns with real‑world intrusion patterns.

### What I Ruled Out
- Reconnaissance commands such as `ls`, `pwd`, or `uname`.
- Benign directory creation.
- Failed or incomplete commands.

Only commands that directly modify authentication mechanisms or file permissions are included.

### Telemetry Used
- Cowrie `cowrie.command.input`
- Full command text
- Session ID
- Source IP
- Timestamp

### MITRE ATT&CK Mapping
- T1098.004 — SSH Authorized Keys  
- T1222 — File and Directory Permissions Modification

### Validation Approach
- Simulated SSH key injection sequences.
- Verified command patterns in Cowrie logs.
- Correlated persistence attempts with Suricata outbound flows.

### False Positives Considered
None. Honeypot users should never modify `.ssh`.

### Detection Improvements
- Add correlation with Suricata outbound C2 traffic.
- Add alerting for repeated persistence attempts from the same IP.
- Add session‑level behavioral scoring.

