# Lab 3 — Network Traffic PCAP Analysis

## Overview
Full network forensics investigation of a 62,965 packet capture.
Identified a confirmed C2 beaconing incident alongside a false positive,
demonstrating real SOC Tier 1 analyst triage methodology.

## Tools Used
- Wireshark (Packet analysis)
- VirusTotal (Threat intelligence)
- Kali Linux terminal (File extraction, sha256sum)

## Key Skills Demonstrated
- Protocol Hierarchy traffic triage
- HTTP stream analysis and TCP following
- JavaScript malware code analysis
- DNS beaconing pattern detection
- False positive vs true positive decision making
- Threat intelligence with VirusTotal
- IOC extraction and documentation

## Attack Scenario
| Item | Detail |
|---|---|
| Attack Type | Malware C2 DNS Beaconing |
| Victim Host | 10.0.2.16 (Ubuntu Linux) |
| C2 Domain | audienceexposure.com |
| Beacon Interval | Every ~5 seconds |
| False Positive | 146.190.62.39 (httpforever.com) |
| MITRE Tactic | T1071 — Application Layer Protocol |

## Investigation Findings
| Indicator | Verdict |
|---|---|
| 151.101.193.91 | ✅ Clean — Fastly CDN |
| 146.190.62.39 (httpforever.com) | ✅ False Positive — normal browsing |
| audienceexposure.com | 🔴 TRUE POSITIVE — DNS C2 beaconing |

## Files
| File | Description |
|---|---|
| `SOC4_Investigation_Report.docx` | Full professional investigation report |
```
