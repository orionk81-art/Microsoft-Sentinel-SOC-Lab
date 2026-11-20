# SOC Investigation Report 004 — Windows Logon Session Correlation

**Project:** Microsoft Sentinel SOC Lab  
**Lab:** 5 — Advanced Windows Authentication Investigation  
**Investigation Date:** November 20, 2026  
**Event Date:** November 17, 2026  
**Data Source:** Local Windows Security Event Log  
**Investigation Status:** Completed — Initial Event Correlation  
**Classification:** Authentication Activity Under Review  
**Severity:** Informational — No Confirmed Incident

---

## 1. Executive Summary

A Windows authentication investigation was conducted using PowerShell to examine successful interactive logon activity recorded on November 17, 2026, at approximately 9:35 PM.

The investigation identified two successful interactive logon events (Event ID 4624) and two corresponding logoff events (Event ID 4634).

Correlation using Windows Logon IDs confirmed that each successful interactive logon had a matching logoff event.

Both authentication sessions began and ended within the same recorded second.

No confirmed malicious activity was identified. However, the available evidence does not establish whether the logons were initiated by an authorized user.

## 2. Investigation Objectives

- Identify successful Windows authentication events.
- Examine unexpected or unverified interactive logon activity.
- Correlate Event IDs 4624 and 4634.
- Match authentication sessions using Logon IDs.
- Review authentication processes and privilege elevation.
- Determine whether the available evidence supports a security incident.

## 3. Tools and Technologies

- Windows PowerShell
- Windows Security Event Logs
- `Get-WinEvent`
- XML event parsing
- Event ID 4624 — Successful Logon
- Event ID 4634 — Account Logoff
- Windows Logon ID correlation
- GitHub for SOC investigation documentation

This investigation used actual Windows event records collected locally. Microsoft Sentinel was not used to ingest or analyze these particular events.

## 4. Evidence Collected

### Authentication Event Timeline

| Timestamp | Event ID | Record ID | Logon ID | Logon Type |
|---|---|---|---|---|
| 9:34:46 PM | 4624 | 234536 | 0x3e7 | 5 |
| 9:34:50 PM | 4624 | 234589 | 0x3e7 | 5 |
| 9:35:01 PM | 4624 | 234785 | 0x1be962c0 | 2 |
| 9:35:01 PM | 4624 | 234786 | 0x1be96334 | 2 |
| 9:35:01 PM | 4634 | 234788 | 0x1be96334 | 2 |
| 9:35:01 PM | 4634 | 234789 | 0x1be962c0 | 2 |

All timestamps are from November 17, 2026, as displayed by the local Windows system.

### Logon Session Correlation

**Session A**

- Successful logon: Event 4624, Record ID 234785
- Logoff: Event 4634, Record ID 234789
- Logon ID: `0x1be962c0`
- Logon Type: 2 — Interactive
- Result: Matching logon and logoff records

**Session B**

- Successful logon: Event 4624, Record ID 234786
- Logoff: Event 4634, Record ID 234788
- Logon ID: `0x1be96334`
- Logon Type: 2 — Interactive
- Result: Matching logon and logoff records

## 5. Authentication Process Analysis

Both interactive logon events contained the following attributes:

| Attribute | Observed Value |
|---|---|
| Logon Process | User32 |
| Authentication Package | Negotiate |
| Process Name | C:\Windows\System32\svchost.exe |
| Logon Type | 2 — Interactive |

The two records differed in their ElevatedToken values.

| Record ID | ElevatedToken | Interpretation |
|---|---|---|
| 234785 | %%1842 | Yes — Elevated token |
| 234786 | %%1843 | No — Non-elevated token |

The observed authentication mechanisms are consistent with legitimate Windows authentication activity.

The presence of an elevated token does not independently establish unauthorized privilege escalation.

## 6. Investigation Findings

### Finding 1 — Two Distinct Interactive Sessions

Two successful interactive logons were recorded at 9:35:01 PM.

The separate Record IDs and Logon IDs establish that these were distinct event records and logon sessions.

### Finding 2 — Successful Session Correlation

Both interactive logons had corresponding Event ID 4634 records with matching Logon IDs.

This supports the conclusion that Windows recorded the creation and termination of both sessions.

### Finding 3 — Short-Lived Authentication Sessions

The successful logons and corresponding logoffs shared the same recorded second.

The
