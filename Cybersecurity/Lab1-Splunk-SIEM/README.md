# 🔐 SIEM Implementation and Threat Detection Using Splunk

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black?style=for-the-badge&logo=splunk&logoColor=green)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-Attacker_Machine-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-Target_Machine-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)

---

## 📌 Project Overview

This project demonstrates the design and implementation of a **Security Information and Event Management (SIEM)** lab using **Splunk Enterprise**. Real-world SSH brute-force attacks were simulated using Hydra and detected using custom **SPL (Search Processing Language)** queries, real-time alerts, and SOC dashboards.

> **Role Target:** SOC Analyst (Tier 1/2) | Security Analyst | Threat Detection Engineer

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|------|---------|
| **Splunk Enterprise** | SIEM platform — log indexing, SPL queries, alerts, dashboards |
| **Kali Linux** | Attacker machine — SSH brute-force simulation |
| **Ubuntu Linux** | Target machine — OpenSSH server, auth log source |
| **Hydra** | Brute-force tool using rockyou.txt wordlist |
| **Splunk Universal Forwarder** | Forwards `/var/log/auth.log` to Splunk indexer |
| **VirtualBox** | Virtualization platform for the lab environment |

---

## 🎯 Objectives

- ✅ Build a SIEM lab using Splunk, Kali Linux, and Ubuntu
- ✅ Collect and ingest Linux authentication logs (`/var/log/auth.log`) into Splunk
- ✅ Simulate SSH brute-force attacks using Hydra + rockyou.txt wordlist
- ✅ Develop SPL detection queries for brute-force and invalid user attempts
- ✅ Configure real-time alerts triggered on attack thresholds
- ✅ Design a SOC Dashboard to visualize attacker behavior

---

## 🏗️ Lab Architecture

```
┌─────────────────┐     SSH Brute-Force      ┌─────────────────┐
│   Kali Linux    │ ───────────────────────► │  Ubuntu Linux   │
│  192.168.50.1   │                          │  192.168.50.4   │
│  (Attacker)     │                          │  (Target/SIEM)  │
└─────────────────┘                          └────────┬────────┘
                                                      │
                                            /var/log/auth.log
                                                      │
                                             Universal Forwarder
                                                      │
                                                      ▼
                                          ┌─────────────────────┐
                                          │  Splunk Enterprise  │
                                          │  localhost:8000     │
                                          │                     │
                                          │  • SPL Queries      │
                                          │  • Real-time Alerts │
                                          │  • SOC Dashboards   │
                                          └─────────────────────┘
```

---

## 🔍 Key SPL Queries

**1. Detect Failed SSH Login Attempts**
```spl
search source=/var/log/auth.log "failed password"
```

**2. Brute-Force Detection (Threshold-Based)**
```spl
index=main sourcetype="linux_secure" "failed password"
| bucket _time span=1m
| stats count by src_ip
| where count>=5
```

**3. Failed Login Timeline**
```spl
index=main sourcetype="linux_secure" "Failed password"
| timechart count
```

**4. Detect Invalid User Login Attempts**
```spl
index=main sourcetype="linux_secure" "invalid user"
| rex "(?i)invalid user (?<extracted_user>\w+) from (?<extracted_ip>\d+\.\d+\.\d+\.\d+)"
| where isnotnull(extracted_user) AND isnotnull(extracted_ip)
| stats count by extracted_user, extracted_ip
| sort - count
```

**5. Detect Privilege Escalation via sudo**
```spl
index=main sourcetype="linux_secure" "sudo"
| rex "sudo:\s+(?<extracted_user>\w+)\s+:"
| where isnotnull(extracted_user)
| stats count by extracted_user
| sort - count
```

**6. Top Attacking IP Addresses**
```spl
index=main sourcetype="linux_secure" "invalid user"
| rex "(?i)invalid user (?<extracted_user>\w+) from (?<extracted_ip>\d+\.\d+\.\d+\.\d+)"
| where isnotnull(extracted_ip)
| stats count by extracted_ip
| sort - count
| head 10
```

---

## 🚨 Alert Configuration

| Setting | Value |
|---------|-------|
| **Alert Name** | Bruteforce Detection |
| **Type** | Real-time |
| **Trigger Condition** | Number of results > 0 in 1 minute |
| **Severity** | High |
| **Throttle** | Suppress for 10 minutes |
| **Action** | Add to Triggered Alerts |

---

## 📊 Results & Key Findings

| Metric | Result |
|--------|--------|
| Total failed login events | **525+ events** in 24-hour window |
| Top attacker IP | **192.168.50.1** (Kali Linux) — ~400 attempts |
| Invalid usernames targeted | **hacker, admin, fakeuser** |
| Brute-force alert | **Fired correctly** — High severity |
| Privilege escalation captured | **22 sudo commands** by user jude |
| Attack peak window | **5:00 PM Mar 6 – 1:00 AM Mar 7, 2026** |

---

## 🚀 How to Reproduce This Lab

1. **Set up VirtualBox** with two VMs on a host-only network:
   - Ubuntu (192.168.50.4) — install OpenSSH: `sudo apt install openssh-server`
   - Kali Linux (192.168.50.1)

2. **Install Splunk Enterprise** on Ubuntu:
   ```bash
   sudo dpkg -i splunk.deb
   sudo /opt/splunk/bin/splunk start
   sudo /opt/splunk/bin/splunk enable boot-start
   ```

3. **Configure data input** in Splunk Web (localhost:8000):
   - Source: `/var/log/auth.log`
   - Source Type: `linux_secure`
   - Index: `main`

4. **Launch Hydra brute-force** from Kali Linux:
   ```bash
   hydra -l jude -P /usr/share/wordlists/rockyou.txt ssh://192.168.50.4 -t 4
   ```

5. **Run SPL queries** in Splunk Search & Reporting to detect the attack.

6. **Configure alerts** and build SOC Dashboard panels.

---

## 🧠 Skills Demonstrated

- SIEM configuration and log ingestion
- SPL (Search Processing Language) query development
- Real-time alert engineering in Splunk
- SOC Dashboard design and visualization
- SSH brute-force simulation with Hydra
- Linux log analysis (`/var/log/auth.log`)
- Network setup with VirtualBox host-only networking
- Threat detection and incident identification

---

## 📁 Repository Structure

```
Splunk-SIEM-Lab/
│
├── README.md                              # Project documentation
├── Splunk_SIEM_Project_Report_Final.docx  # Full report with screenshots
└── screenshots/                           # Evidence from the lab
    ├── splunk_add_data_review.png
    ├── auth_log_search_441_events.png
    ├── ssh_service_status.png
    ├── kali_ssh_login.png
    ├── ssh_failed_attempts.png
    ├── hydra_attack_1.png
    ├── hydra_attack_2.png
    ├── alert_settings.png
    ├── alert_trigger_config.png
    ├── triggered_alerts_fired.png
    ├── brute_force_query_result.png
    ├── invalid_user_chart.png
    ├── sudo_usage_chart.png
    ├── top_attacker_ip_chart.png
    ├── timechart_visualization.png
    ├── soc_dashboard_overview.png
    └── failed_login_timeline.png
```

---

## 👤 Author

**Manmeet Kaur**
Cybersecurity Enthusiast | SOC Analyst 


---

## 📄 License

This project is for educational purposes only. All attack simulations were conducted in an isolated, controlled lab environment.

---

> *"The best defense is understanding the offense."*
