# SOC Threat Detection & Investigation Using Splunk

**Author**: Alpar Arman  
**Date**: April 2025  
**Target Role**: Cyber Security Analyst 

---

## Project Purpose

Build a mini-SOC in a single laptop-scale lab to demonstrate the ability to:

- Collect multi-platform logs (Windows Sysmon + Apache) with Splunk
- Generate realistic attacks (SSH brute-force, web enumeration, POST exfiltration)
- Detect and visualise those attacks in live dashboards
- Trigger automated alerts and outline a logical incident-response workflow

---

## High-Level Architecture

VirtualBox network `192.168.56.0/24` (host-only) + NAT for updates:

| Machine              | Software Details                                         |
|----------------------|-----------------------------------------------------------|
| **Ubuntu 22.04**      | Splunk Enterprise 9.4 (indexer)                            |
|                      | - Universal Forwarder: Receives on TCP 9997                |
|                      | - Apache 2.4: Access / Error logs → UF → Splunk             |
|                      | - IP: 192.168.56.105                                        |
| **Windows 10 Home**   | Sysmon 15.15 (SwiftOnSecurity config)                      |
|                      | - OpenSSH Server: Security + Sysmon → UF → Splunk          |
|                      | - IP: 192.168.56.106                                        |
| **Kali 2024.1**       | Hydra 9.5, Gobuster 3.6, curl, nmap                        |
|                      | - IP: 192.168.56.103                                        |

**All logs are indexed in Splunk as `index=main` with sourcetypes**:
- `WinEventLog:Security`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- `apache:access`
- `apache:error`

---

## Quick-Start

### Prerequisites

- VirtualBox ≥7 with host-only network enabled
- 8 GB RAM free for three VMs
- Splunk Enterprise Linux `.deb` installer (free license)

### Clone Repository

```bash
git clone https://github.com/<your-repo>/soc-splunk-lab.git
```

Import the three OVA templates or build from ISO, then follow `docs/setup-steps.txt`.

### Start Splunk on Ubuntu

```bash
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk start
```
*(On both Windows and Ubuntu for forwarders)*

### Verify Data Flow

Go to Splunk UI → Search & Reporting → and run:

```spl
index=main | stats count by sourcetype
```

Confirm that data is flowing correctly into Splunk.

---

## Attack Simulations

- **SSH brute-force**:
  ```bash
  hydra -l arman -P rockyou.txt ssh://192.168.56.106
  ```
- **Web directory busting**:
  ```bash
  gobuster dir -u http://192.168.56.105/ -w /usr/share/wordlists/dirb/common.txt
  ```
- **POST flood (exfiltration)**:
  ```bash
  for i in {1..500}; do curl -X POST -d "ex$i" http://192.168.56.105/; done
  ```

> *Port-scan detection was researched but omitted from final scope to keep project concise.*

---

## Detection Logic (Core SPL Snippets)

- **Failed login spike**:
  ```spl
  index=main EventCode=4625
  | bin _time span=5m
  | stats count
  | where count>100
  ```

- **404 spike**:
  ```spl
  index=main sourcetype=apache:access status=404
  | bin _time span=5m
  | stats count
  ```

- **POST spike**:
  ```spl
  index=main sourcetype=apache:access "POST"
  | bin _time span=1m
  | stats count
  ```

---

## Dashboards and Alerts

### Dashboard: SOC Threat Detection

- **Panel 1**: Top attacked usernames (bar chart)
- **Panel 2**: 404 errors over time (line chart)
- **Panel 3**: Suspicious POST requests over time (line chart)

### Alerts (SavedSearches)

- **Bruteforce Detected**:
  - Schedule: every 5 minutes (`cron */5 * * * *`)
  - Trigger: EventCode 4625 count >100 in 5 minutes
- **404 Flood**:
  - Schedule: every 5 minutes
  - Trigger: status 404 count >20 in 5 minutes

---

## Incident-Response Highlights

- Block brute-force IP using `netsh advfirewall` on Windows
- Drop enumeration IP using `iptables` on Ubuntu
- Rate-limit POST size using Apache `mod_evasive`
- Full response steps documented in `IR_Playbook.md`

---

## Repository Map

```
dashboards/      # JSON exports of all Splunk panels
spl/             # All SPL queries (detections, alerts)
evidence/        # Screenshots of alerts and dashboards
IR_Playbook.md   # Detailed incident-response steps
README.md        # This file
SOC_Threat_Detection_Report.md # Formal report
```

---

## Lessons Learned

- Custom field extraction is **mandatory** for accurate Apache analytics.
- Sysmon needs **completed handshakes**; IDS or Zeek is better for SYN-scan noise.
- **Small, focused dashboards** outperform large, complex ones during recruiter demos.
- **500 MB/day** free Splunk license is sufficient if unnecessary Windows logs are trimmed.
