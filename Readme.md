Layered Network Security Monitoring & Fusion Detection Framework
Suricata IDS + Cowrie Honeypot + Splunk Correlation Architecture
Project Overview

This graduate-level project implements a layered intrusion detection and deception monitoring architecture using:

Suricata Network IDS

Cowrie SSH/Telnet Honeypot

Splunk Enterprise SIEM

Structured Incident Response Playbooks

Risk Quantification Model

Multi-Stage Kill Chain Correlation

The system aggregates network-level intrusion detection data and host-level attacker interaction telemetry to:

Detect exploit attempts

Identify persistence behavior

Monitor malware delivery

Correlate multi-stage attack progression

Quantify cyber risk exposure

Provide executive-level security reporting

Executive Metrics

Total Observed Attack Events: 307,708

High-Severity Exploit Attempts: 30,649

Confirmed Multi-Stage Kill Chains: 18

Persistence Attempts: 109

Unique Malware Payloads Observed: 60

Architecture
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

This layered model enables:

Early exploit detection (network layer)

Post-authentication behavior tracking (host layer)

Malware staging visibility

Intrusion lifecycle reconstruction

Risk-based reporting

Detection Engineering Modules
Detection 1: High-Severity Exploit Attempts (Suricata)

Severity 1–2 Suricata alerts represent the most dangerous exploit categories, including:

DoublePulsar backdoor communication

Apache ActiveMQ RCE attempts

Dovecot memory corruption

/bin/sh URI shell execution attempts

SPL
index=suricata event_type=alert
| rex field=alert "'severity':\s*(?<severity>\d+)"
| rex field=alert "'signature':\s*'(?<signature>[^']+)'"
| where severity<=2
| stats count by severity signature
| sort severity -count
MITRE ATT&CK Mapping

T1203 – Exploitation for Client Execution

T1210 – Exploitation of Remote Services

Detection 2: Malware File Transfers (Suricata)

Repeated downloads of identical MD5 hashes indicated active malware distribution infrastructure.

Examples observed:

fb7cb2f4584c06d71077b3970b54aad3

ac56291293ec6186a86afc3495db6b7f

SPL
index=suricata event_type=fileinfo
| rex field=fileinfo "'filename':\s*'(?<filename>[^']+)'"
| rex field=fileinfo "'md5':\s*'(?<md5>[a-f0-9]{32})'"
| rex field=fileinfo "'magic':\s*'(?<magic>[^']+)'"
| search magic="*script*" OR magic="*executable*" OR filename="*.sh" OR filename="*.bin" OR filename="*.exe"
| stats count by src_ip filename md5 magic
| sort -count
MITRE ATT&CK Mapping

T1105 – Ingress Tool Transfer

Detection 3: SSH Key Injection & Persistence (Cowrie)

Attackers attempted:

.ssh deletion and recreation

SSH public key injection

File immutability modification (chattr -ia)

SPL
index=cowrie eventid="cowrie.command.input"
| search input="*authorized_keys*" OR input="*rm -rf .ssh*" OR input="*mkdir .ssh*" OR input="*chattr -ia*" OR input="*lockr -ia*"
| stats count by src_ip input
| sort -count
MITRE ATT&CK Mapping

T1098.004 – SSH Authorized Keys

T1222 – File and Directory Permissions Modification

Detection 4: Malware Download Attempts (Cowrie)

Attackers used:

wget

curl

direct /dl/<hash> paths

SPL
index=cowrie eventid="cowrie.command.input"
| search input="wget*" OR input="curl*" OR input="*dl/*"
| stats count by src_ip input
| sort -count
MITRE ATT&CK Mapping

T1105 – Ingress Tool Transfer

T1059 – Command and Scripting Interpreter

Fusion Correlation Layer

This project correlates Suricata and Cowrie telemetry to reconstruct confirmed intrusion lifecycles:

Suricata exploit attempt

Cowrie session creation

Cowrie command execution

Suricata malware file transfer

Attack Progression Rate

High-Severity Exploit Attempts: 30,649

Confirmed Multi-Stage Kill Chains: 18

Attack Progression Rate:

(18 / 30649) * 100 = 0.06%

Less than 0.1% of exploit attempts progressed into multi-stage activity, indicating widespread automation but limited escalation success.

Executive Risk Quantification
Detection Type	Likelihood	Impact	Risk Score
High-Severity Exploit	4	5	20
Persistence Attempt	3	5	15
Malware Transfer	4	4	16

Risk Score = Likelihood × Impact

This ties detection engineering to cybersecurity risk management principles.

Incident Response Integration

Each detection is supported by structured playbooks covering:

Triage

Escalation thresholds

Evidence preservation

Chain of custody

Containment

Eradication

Recovery

Post-incident review

This ensures repeatable and standardized handling of attacker activity.

Key Findings

Large-scale automated scanning dominates attack volume

Botnet-driven exploit campaigns target exposed services

Identical malware hashes reused across sessions

Persistence attempts follow successful authentication

Very low confirmed multi-stage escalation rate

Technologies Used

Suricata IDS

Cowrie Honeypot

T-Pot Platform

Splunk Enterprise

MITRE ATT&CK Framework

Custom SPL Queries

Risk Scoring Model

Conclusion

This project demonstrates a fully layered detection and response framework that integrates:

Network intrusion detection

Host-level deception telemetry

Multi-stage correlation analytics

Incident response playbooks

Executive risk reporting

It bridges Security Operations, Threat Intelligence, Incident Response, and Cyber Risk Management into a unified monitoring architecture.