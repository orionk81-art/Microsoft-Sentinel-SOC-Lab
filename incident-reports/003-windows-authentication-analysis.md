# SOC Investigation Report 003 — Windows Authentication Log Analysis

**Project:** Microsoft Sentinel SOC Lab  
**Lab:** 4 — Windows Security Event Investigation  
**Data Source:** Local Windows Security Event Log  
**Event ID:** 4624 — Successful Logon  
**Analysis Date:** November 20, 2026  
**Investigation Status:** Completed — Initial Review  
**Classification:** Security Telemetry Analysis — No Confirmed Incident

---

## 1. Executive Summary

A security investigation was conducted using Windows PowerShell to examine actual Windows authentication events.

The investigation analyzed 484 successful logon events collected from the local Windows Security Event Log.

The analysis identified 471 service logons, 12 interactive logons, and one system logon.

Service authentication accounted for approximately 97.3% of the sampled events.

No confirmed malicious activity was identified from the available aggregated evidence.

## 2. Investigation Objectives

- Identify successful Windows authentication activity.
- Examine Windows Security Event ID 4624.
- Categorize authentication events by logon type.
- Identify potentially unusual authentication patterns.
- Establish an initial authentication activity baseline.
- Document findings using SOC investigation practices.

## 3. Tools and Technologies

- Windows PowerShell
- Windows Event Logging
- Windows Security Event ID 4624
- XML event parsing
- GitHub for investigation documentation

Microsoft Sentinel is part of the broader portfolio environment, but this investigation used local Windows logs rather than Sentinel-ingested telemetry.

## 4. Evidence Collection

PowerShell was used to retrieve up to 500 successful logon events within a seven-day search window.

The following results were obtained:

| Logon Type | Description | Event Count | Percentage |
|---|---|---:|---:|
| 5 | Service logon | 471 | 97.3% |
| 2 | Interactive logon | 12 | 2.5% |
| 0 | System logon | 1 | 0.2% |
| **Total** | | **484** | **100%** |

These figures describe the retrieved sample, not necessarily every authentication event during the seven-day period.

## 5. Investigation Findings

### Finding 1 — Service Authentication Activity

A total of 471 successful logons were classified as Logon Type 5.

This logon type is commonly associated with Windows services.

The high number of service logons does not independently establish malicious behavior.

### Finding 2 — Interactive Logons

Twelve successful events were classified as Logon Type 2.

These events represent interactive local logons.

Additional account and session context would be necessary to determine whether any activity was unauthorized.

### Finding 3 — System Logon

One successful authentication event was classified as Logon Type 0.

The event was recorded but was not identified as malicious based on the available information.

### Finding 4 — Remote Desktop Activity

No Logon Type 10 events appeared in the retrieved sample.

This finding does not rule out Remote Desktop activity outside the sampled records.

## 6. Security Assessment

**Finding:** No confirmed security incident.

**Evidence limitations:** The investigation used aggregated logon type counts. Account identities, source addresses, authentication processes, and detailed timelines were not analyzed.

**Assessment:** The observed distribution is compatible with routine Windows authentication activity, but additional investigation would be required to establish whether individual events were authorized.

## 7. Recommended Next Steps

1. Review authentication account and process details.
2. Examine logon timestamps for unexpected patterns.
3. Investigate any unexpected Remote Desktop activity.
4. Correlate successful logons with failed authentication attempts when available.
5. Develop additional Windows authentication detection scripts.
6. Expand the lab to include Microsoft Sentinel ingestion when feasible.

## 8. MITRE ATT&CK Context

Relevant techniques for future investigation include:

- **T1078 — Valid Accounts:** Adversaries may abuse legitimate credentials.
- **T1110 — Brute Force:** Repeated authentication attempts may indicate password attacks.
- **T1021.001 — Remote Desktop Protocol:** Adversaries may use RDP for remote access.

These are potential detection use cases, not techniques confirmed in this investigation.

## 9. Conclusion

This exercise demonstrated the ability to retrieve, parse, categorize, and analyze actual Windows authentication events using PowerShell.

The investigation established an initial sample-based authentication baseline and documented the findings in a structured SOC report.

No confirmed unauthorized access or account compromise was established.

---

**Portfolio Disclosure:** This report uses actual local Windows Security Event Log counts. Sensitive account identifiers have been excluded. The investigation was conducted locally using PowerShell and did not involve live Microsoft Sentinel alert generation.
