# MITRE ATT&CK Mapping
**Project:** Project Citadel | **Organisation:** Nexus Financial Services  
**Engineer:** Tobi Babalola | **Framework:** MITRE ATT&CK v14

---

## Overview

This document maps all simulated attack techniques and defensive controls implemented in Project Citadel to the MITRE ATT&CK framework. The goal is to demonstrate attacker mindset awareness, detection engineering capability, and alignment with industry-standard threat categorisation.

---

## Technique Mapping

| Tactic | Technique | ID | Simulation | Detection | Response |
|--------|-----------|-----|------------|-----------|----------|
| Initial Access | Brute Force: Password Guessing | T1110.001 | 15 failed SSH attempts from single IP (197.210.52.203) against Citadel-VM | Sentinel KQL rule - 3+ failed attempts from same IP within 5 minutes. VM-side journalctl confirmation | Attacker IP blocked via Citadel-NSG deny rule at priority 105 |
| Initial Access | Valid Accounts | T1078 | SSH attempts targeting `azureuser`  a known valid account on the system | Syslog auth/authpriv events showing targeted username in Log Analytics | MFA enforced on all Entra ID accounts. RBAC scoped to least privilege |
| Discovery | Network Service Discovery | T1046 | Port 22 targeted directly implies prior reconnaissance of exposed services | NSG flow logs. Azure Activity logs in Citadel-LAW | NSG rules restrict SSH to engineer IP only. All other inbound traffic denied |
| Defense Evasion | Use Alternate Authentication Material | T1550 | Attacker attempted SSH key bypass using invalid key file | SSH daemon rejected at preauth stage - logged as Connection reset in journalctl | Password authentication disabled. SSH key auth enforced. Root login disabled |
| Initial Access | Exploit Public-Facing Application | T1190 | VM exposed on public IP with port 22 open, exploitable surface for any attacker with network access | Azure Defender for Cloud flagged open management ports as a recommendation. NSG inbound rules reviewed | Public IP exposure documented as known gap. Recommended fix: Azure Bastion deployment to eliminate direct VM public IP |

---

## Detection Coverage Summary

| Technique | Detected | Tool Used | Alert Configured |
|-----------|----------|-----------|-----------------|
| T1110.001 | YES | Microsoft Sentinel + Log Analytics | Citadel-Rule-FailedLogins |
| T1078 | YES | Log Analytics Syslog | Partial - MFA configured, no dedicated alert |
| T1046 | NO | NSG logs - implicit | No dedicated rule |
| T1550 | YES | VM journalctl + Syslog | Captured in Citadel-Rule-FailedLogins |
| T1190 | NO | Defender for Cloud recommendation | No dedicated alert, gap documented |

---

## Defensive Controls Mapped

| Control | Technique Mitigated | Implementation |
|---------|-------------------|----------------|
| SSH key authentication only | T1110.001, T1078 | PasswordAuthentication no in sshd_config |
| Root login disabled | T1078, T1110.001 | PermitRootLogin no in sshd_config |
| NSG IP allowlist | T1190, T1046 | Allow-SSH-MyIP at priority 100, Deny-All at 200 |
| MFA enforced | T1078 | Enabled on all Entra ID accounts |
| RBAC least privilege | T1078 | Reader role only - no write permissions by default |
| Sentinel detection rule | T1110.001 | KQL threshold rule - 3 failed attempts in 5 minutes |
| IP block response | T1110.001 | NSG deny rule added for attacker IP post-detection |
| Key Vault managed identity | T1078 | No hardcoded credentials anywhere in environment |

---

## Known Detection Gaps & Recommendations

| Gap | Technique | Recommendation |
|-----|-----------|----------------|
| No Azure Bastion | T1190 | Deploy Bastion, eliminates VM public IP exposure entirely |
| No automated response | T1110.001 | Build Logic Apps playbook to auto-block IPs when Sentinel alert fires |
| No dedicated T1046 rule | T1046 | Create NSG flow log alert for port scanning patterns |
| No T1078 behavioural baseline | T1078 | Enable Entra ID Identity Protection for anomalous login detection |

---

* Nexus Financial Services | MITRE ATT&CK v14*
