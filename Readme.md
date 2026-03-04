

pasted
# Layered Network Security Monitoring & Fusion Detection Framework

**Suricata IDS + Cowrie Honeypot + Splunk Correlation Architecture**

> CYBR 535 – Graduate Final Project | March 2026

**Group 1** — Megan Geer · Jordan Holloway · Maxine Jones · Kristi Raines · Tyler Skirble

---

##  Table of Contents

- [Project Overview](#project-overview)
- [Executive Metrics](#executive-metrics)
- [Architecture](#architecture)
- [Detection Engineering Modules](#detection-engineering-modules)
  - [Detection 1: High-Severity Exploit Attempts](#detection-1-high-severity-exploit-attempts-suricata)
  - [Detection 2: Malware File Transfers](#detection-2-malware-file-transfers-suricata)
  - [Detection 3: SSH Key Injection & Persistence](#detection-3-ssh-key-injection--persistence-cowrie)
  - [Detection 4: Malware Download Attempts](#detection-4-malware-download-attempts-cowrie)
- [Fusion Correlation Layer](#fusion-correlation-layer)
- [Executive Risk Quantification](#executive-risk-quantification)
- [Incident Response Integration](#incident-response-integration)
- [Key Findings](#key-findings)
- [Lab Setup Guide](#lab-setup-guide)
- [Technologies Used](#technologies-used)
- [Conclusion](#conclusion)
- [References](#references)

---

## Project Overview

This graduate-level project implements a layered intrusion detection and deception monitoring architecture using:

| Component | Role |
|---|---|
| **Suricata Network IDS** | Network-layer exploit and malware detection |
| **Cowrie SSH/Telnet Honeypot** | Host-level attacker interaction telemetry |
| **Splunk Enterprise SIEM** | Log aggregation, analytics, and correlation |
| **Structured Incident Response Playbooks** | Repeatable, standardized response workflows |
| **Risk Quantification Model** | Likelihood × Impact scoring aligned to business risk |
| **Multi-Stage Kill Chain Correlation** | Cross-source attack lifecycle reconstruction |

The system aggregates network-level intrusion detection data and host-level attacker interaction telemetry to:

- Detect exploit attempts
- Identify persistence behavior
- Monitor malware delivery
- Correlate multi-stage attack progression
- Quantify cyber risk exposure
- Provide executive-level security reporting

---

## Executive Metrics

| Metric | Value |
|---|---|
| Total Observed Attack Events | **307,708** |
| High-Severity Exploit Attempts | **30,649** |
| Confirmed Multi-Stage Kill Chains | **18** |
| Persistence Attempts | **109** |
| Unique Malware Payloads Observed | **60** |

---

## Architecture

```
Internet Traffic
        ↓
Suricata IDS (Network Detection)
        ↓
T-Pot Honeypot Environment
        ↓
Cowrie SSH/Telnet Honeypot (Host Interaction)
        ↓
Splunk SIEM (Analytics + Correlation)
        ↓
Executive & Technical Dashboards
```

This layered model enables:

- **Early exploit detection** — network layer
- **Post-authentication behavior tracking** — host layer
- **Malware staging visibility**
- **Intrusion lifecycle reconstruction**
- **Risk-based reporting**

---

## Detection Engineering Modules

### Detection 1: High-Severity Exploit Attempts (Suricata)

Severity 1–2 Suricata alerts represent the most dangerous exploit categories, including:

- DoublePulsar backdoor communication
- Apache ActiveMQ RCE attempts
- Dovecot memory corruption
- `/bin/sh` URI shell execution attempts

**SPL Query:**

```spl
index=suricata event_type=alert
| rex field=alert "'severity':\s*(?<severity>\d+)"
| rex field=alert "'signature':\s*'(?<signature>[^']+)'"
| where severity<=2
| stats count by severity signature
| sort severity -count
```

**MITRE ATT&CK Mapping:**

| Technique ID | Technique Name |
|---|---|
| T1203 | Exploitation for Client Execution |
| T1210 | Exploitation of Remote Services |

---

### Detection 2: Malware File Transfers (Suricata)

Repeated downloads of identical MD5 hashes indicated active malware distribution infrastructure.

**Examples observed:**
- `fb7cb2f4584c06d71077b3970b54aad3`
- `ac56291293ec6186a86afc3495db6b7f`

**SPL Query:**

```spl
index=suricata event_type=fileinfo
| rex field=fileinfo "'filename':\s*'(?<filename>[^']+)'"
| rex field=fileinfo "'md5':\s*'(?<md5>[a-f0-9]{32})'"
| rex field=fileinfo "'magic':\s*'(?<magic>[^']+)'"
| search magic="*script*" OR magic="*executable*" OR filename="*.sh" OR filename="*.bin" OR filename="*.exe"
| stats count by src_ip filename md5 magic
| sort -count
```

**MITRE ATT&CK Mapping:**

| Technique ID | Technique Name |
|---|---|
| T1105 | Ingress Tool Transfer |

---

### Detection 3: SSH Key Injection & Persistence (Cowrie)

Attackers attempted:

- `.ssh` deletion and recreation
- SSH public key injection
- File immutability modification (`chattr -ia`)

**SPL Query:**

```spl
index=cowrie eventid="cowrie.command.input"
| search input="*authorized_keys*" OR input="*rm -rf .ssh*" OR input="*mkdir .ssh*" OR input="*chattr -ia*" OR input="*lockr -ia*"
| stats count by src_ip input
| sort -count
```

**MITRE ATT&CK Mapping:**

| Technique ID | Technique Name |
|---|---|
| T1098.004 | SSH Authorized Keys |
| T1222 | File and Directory Permissions Modification |

---

### Detection 4: Malware Download Attempts (Cowrie)

Attackers used `wget`, `curl`, and direct `/dl/<hash>` paths to stage malware.

**SPL Query:**

```spl
index=cowrie eventid="cowrie.command.input"
| search input="wget*" OR input="curl*" OR input="*dl/*"
| stats count by src_ip input
| sort -count
```

**MITRE ATT&CK Mapping:**

| Technique ID | Technique Name |
|---|---|
| T1105 | Ingress Tool Transfer |
| T1059 | Command and Scripting Interpreter |

---

## Fusion Correlation Layer

This project correlates Suricata and Cowrie telemetry to reconstruct confirmed intrusion lifecycles:

```
[1] Suricata exploit attempt
        ↓
[2] Cowrie session creation
        ↓
[3] Cowrie command execution
        ↓
[4] Suricata malware file transfer
```

### Attack Progression Rate

| Stage | Count |
|---|---|
| High-Severity Exploit Attempts | 30,649 |
| Confirmed Multi-Stage Kill Chains | **18** |
| **Escalation Rate** | **~0.06%** |

> Less than **0.1%** of exploit attempts progressed into multi-stage activity, indicating widespread automation but limited escalation success.

---

## Executive Risk Quantification

> **Risk Score = Likelihood × Impact**

| Detection Type | Likelihood (1–5) | Impact (1–5) | Risk Score |
|---|:---:|:---:|:---:|
| High-Severity Exploit | 4 | 5 | **20** |
| Persistence Attempt | 3 | 5 | **15** |
| Malware Transfer | 4 | 4 | **16** |

This ties detection engineering directly to cybersecurity risk management principles.

---

## Incident Response Integration

Each detection is supported by structured playbooks covering:

1. **Triage**
2. **Escalation thresholds**
3. **Evidence preservation**
4. **Chain of custody**
5. **Containment**
6. **Eradication**
7. **Recovery**
8. **Post-incident review**

This ensures repeatable and standardized handling of attacker activity.

---

## Key Findings

- Large-scale **automated scanning** dominates attack volume
- **Botnet-driven exploit campaigns** target exposed services
- **Identical malware hashes** reused across sessions
- **Persistence attempts** follow successful authentication
- **Very low** confirmed multi-stage escalation rate (~0.06%)

---

## Lab Setup Guide

### 1. Deploy T-Pot on AWS

```bash
# Launch Ubuntu EC2 instance (t2.medium or higher recommended)
# Open required ports: 22, 80, 443, etc.

# Install Docker & Docker Compose, then:
git clone https://github.com/telekom-security/tpotce
cd tpotce
sudo ./install.sh

# Reboot after installation, then verify containers
docker ps
```

### 2. Configure Log Forwarding

- Enable **Suricata EVE JSON** logging
- Confirm **Cowrie JSON** logging is enabled
- Forward logs to Splunk via:
  - Universal Forwarder, **or**
  - Manual extraction + CSV ingestion

### 3. Splunk Setup

```bash
# Create indexes
index = suricata
index = cowrie
```

- Ingest JSON logs
- Configure field extractions
- Build dashboards using the provided SPL queries above

### 4. Validate Data Collection

```spl
index=suricata | stats count
index=cowrie | stats count
```

Ensure telemetry is being indexed correctly before building detections.

### 5. Optional: Automate Log Extraction

Develop a Python script to:

1. SSH into the EC2 instance
2. Pull latest log files
3. Convert JSON to structured CSV
4. Ingest into Splunk

---

## Technologies Used

| Tool | Purpose |
|---|---|
| [Suricata IDS](https://suricata.io/) | Network intrusion detection |
| [Cowrie Honeypot](https://github.com/cowrie/cowrie) | SSH/Telnet deception & telemetry |
| [T-Pot Platform](https://github.com/telekom-security/tpotce) | Honeypot orchestration |
| [AWS EC2](https://aws.amazon.com/ec2/) | Cloud deployment infrastructure |
| [Splunk Enterprise](https://www.splunk.com/) | SIEM, analytics, dashboards |
| Python | Log automation scripting |
| [MITRE ATT&CK](https://attack.mitre.org/) | Threat technique mapping |
| Risk Scoring Model | Likelihood × Impact quantification |

---

## Conclusion

This project demonstrates a fully layered detection and response framework integrating:

- Network intrusion detection
- Host-level deception telemetry
- Multi-stage correlation analytics
- Incident response playbooks
- Executive risk reporting

It bridges **Security Operations**, **Threat Intelligence**, **Incident Response**, and **Cyber Risk Management** into a unified monitoring architecture aligned with enterprise SOC standards.

---

## References

ATT&CK based SOC assessments training | MITRE ATT&CK®. (n.d.-b). https://attack.mitre.org/resources/learn-more-about-attack/training/soc-assessments/

Jones, M. (2025). From honeypot noise to actionable risk: Building a fusion-based ML IDS. Medium. https://medium.com/@mkj00015/from-honeypot-noise-to-actionable-risk-building-a-fusion-based-ml-ids-41e6838812dd

Kral, P. (n.d.). The incident handlers handbook. SANS Institute. https://sansorg.egnyte.com/dl/SzUc95nE0x

Nelson, A., Rekhi, S., Souppaya, M., Scarfone, K., Computer Security Division, Information Technology Laboratory, National Institute of Standards and Technology, Cichonski, P., Millar, T., Grance, T., & Scarfone, K. (2012). Computer security incident handling guide. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

