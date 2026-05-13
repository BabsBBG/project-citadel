# Cyber Threat Intelligence Integration
**Project:** Project Citadel | **Organisation:** Nexus Financial Services  
**Engineer:** Tobi Babalola | **Date:** May 2026

---

## Overview

This document covers the Cyber Threat Intelligence (CTI) integration i built on top of Project Citadel's existing SIEM infrastructure. The objective was to move Sentinel from purely reactive detection to proactive threat-informed defence  correlating environment activity against known malicious indicators before an attack completes.

---

## Architecture
AlienVault OTX (TAXII Feed)          Manual IOC Upload
│                                  │
└──────────────┬───────────────────┘
│
ThreatIntelligenceIndicator
(Citadel-LAW)
│
┌─────────▼──────────┐
│  Sentinel Analytics │
│  Citadel-Rule-      │
│  ThreatIntelMatch   │
└─────────┬──────────┘
│
┌─────────▼──────────┐
│  Incident Created   │
│  Citadel-SOC-       │
│  Dashboard          │
└─────────┬──────────┘
│
┌─────────▼──────────┐
│  ITIL Response      │
│  Workflow           │
└────────────────────┘

---

## Threat Intelligence Sources

| Source | Type | Method | Indicators |
|--------|------|--------|------------|
| AlienVault OTX | External feed | TAXII 2.1 connector | IPs, domains, file hashes |
| Manual IOCs | Internal | Direct upload to Sentinel TI | Attacker IPs, phishing domains |

### Manual Indicators Uploaded

| Name | Type | Value | Threat Type | Confidence |
|------|------|-------|-------------|------------|
| Known-TorExitNode-01 | IP | 185.220.101.45 | malicious-activity | 85% |
| Citadel-INC001-AttackerIP | IP | 197.210.52.203 | malicious-activity | 100% |
| Simulated-PhishingDomain-01 | Domain | malicious-domain-nexus.com | phishing | 75% |

---

## Detection Rules

### Rule 1 — Threat Intelligence Match
**Name:** `Citadel-Rule-ThreatIntelMatch`  
**Severity:** High  
**Logic:** Correlates Syslog events against known malicious IPs in ThreatIntelligenceIndicator table

```kusto
let ThreatIPs = ThreatIntelligenceIndicator
| where isnotempty(NetworkIP)
| where TimeGenerated > ago(7d)
| summarize by NetworkIP;
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "197.210.52.203"
   or SyslogMessage has_any (ThreatIPs)
| project TimeGenerated, HostName, SyslogMessage
```

### Rule 2 — Failed Sign-ins (Identity Layer)
**Name:** `Citadel-Rule-FailedSignins`  
**Severity:** Medium  
**Logic:** Detects 3+ failed Entra ID sign-in attempts from same IP within 5 minutes

```kusto
SigninLogs
| where ResultType != 0
| where TimeGenerated > ago(5m)
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

---

## SOC Dashboard

Built `Citadel-SOC-Dashboard` workbook in Microsoft Sentinel with three panels:

| Panel | Query Source | Visualization | Purpose |
|-------|-------------|---------------|---------|
| Failed Login Attempts — Last 24 Hours | Syslog auth/authpriv | Line chart | Track brute force activity over time |
| Top Attacker IPs | Syslog parsed source IPs | Bar chart | Identify most active threat sources |
| Threat Intelligence Indicators | ThreatIntelligenceIndicator | Table | Live view of known bad indicators |

---

## ITIL Incident Lifecycle - INC-001 Mapped

### 1. Detection
**Tool:** Microsoft Sentinel analytics rule `Citadel-Rule-FailedLogins`  
**Event:** 15 failed SSH authentication attempts from `197.210.52.203` within 4-minute window  
**Trigger:** KQL threshold rule fired - FailedAttempts >= 3 from same source IP  

### 2. Logging
**Tool:** Azure Monitor + Log Analytics (`Citadel-LAW`)  
**Evidence collected:**
- VM-side: `journalctl -u ssh` - all 15 connection resets at preauth stage
- Cloud-side: Syslog auth/authpriv - attacker IP confirmed in Log Analytics pipeline
- AzureActivity logs - subscription-level activity captured via Azure Activity connector

### 3. Investigation
**Analyst actions:**
- Queried `Syslog` in Citadel-LAW - confirmed source IP `197.210.52.203`
- Cross-referenced against ThreatIntelligenceIndicator table - IP manually added as known malicious indicator with 100% confidence
- Reviewed NSG flow logs - confirmed no successful connection established
- Verified no lateral movement or data access occurred

### 4. Response
**Action taken:** Added deny rule to `Citadel-NSG`  
**Rule:** `Deny-Attacker-IP` - Source: `197.210.52.203`, Priority: 105, Action: Deny  
**Effect:** All further connection attempts from attacker IP dropped at network layer before reaching VM

### 5. Recovery
**Actions:**
- Confirmed VM operational post-incident - SSH connectivity verified from authorised IP
- Verified no configuration changes made during attack window
- Confirmed all security controls (SSH key auth, root disabled, password auth off) remained intact
- NSG rule verified active and blocking

### 6. Lessons Learned
**What worked:**
- SSH hardening prevented any successful authentication despite 15 attempts
- Log pipeline (DCR → Syslog → LAW) captured full attack timeline
- Manual investigation + containment completed in under 10 minutes

**What to improve:**
- Deploy Azure Bastion - eliminate VM public IP exposure entirely
- Automate response via Logic Apps playbook - Sentinel alert should auto-trigger NSG block without manual intervention
- Enable fail2ban on VM - OS-level auto-blocking after repeated failures
- Configure Sentinel watchlist for known attacker IPs - faster cross-referencing during investigation

---

## Key Takeaways

1. **Proactive beats reactive.** Uploading `197.210.52.203` as a threat indicator means any future connection attempt from that IP is flagged before a detection rule even needs to fire.

2. **TAXII feeds multiply coverage.** AlienVault OTX pulled 1,270+ indicators automatically - no manual work required after initial configuration. Every one of those is a known bad actor being watched for in the environment.

3. **Identity logs complete the picture.** Entra ID SigninLogs flowing into Citadel-LAW means the detection coverage now spans both the network layer (SSH brute force) and the identity layer (Azure AD credential attacks) - two of the most common initial access vectors.

4. **ITIL alignment matters.** Every security event follows the same lifecycle - detect, log, investigate, respond, recover, learn. Mapping to ITIL shows security operations fit into organisational process, not just technical tooling.

---

*Project Citadel - Nexus Financial Services | CTI Integration*