# SOC Investigation Report 005 — Automated Authentication Detection

**Project:** Microsoft Sentinel SOC Lab  
**Lab:** 6 — Automated Windows Threat Detection  
**Investigation Date:** November 20, 2026  
**Data Source:** Local Windows Security Event Logs  
**Tool:** Windows PowerShell  
**Status:** Completed  
**Severity:** Informational

## 1. Executive Summary

An automated Windows authentication detection script was executed against locally available Windows Security Event Logs.

The script analyzed successful and failed authentication events over a seven-day lookback period and checked for repeated failed logons and successful Remote Desktop sessions.

The investigation returned 454 successful logon events (Event ID 4624). No failed logon events (Event ID 4625) or successful Remote Desktop logons (Logon Type 10) were returned.

No security incident was confirmed.

## 2. Detection Methodology

The PowerShell script used `Get-WinEvent` to retrieve authentication records and XML parsing to extract relevant security attributes.

The detection logic included:

- Event ID 4624 — Successful authentication
- Event ID 4625 — Failed authentication
- Logon Type 10 — Remote interactive authentication
- Failed logon threshold — Five or more failures per account within seven days

The failure threshold is an initial heuristic and does not establish brute-force activity by itself.

## 3. Detection Results

| Detection Category | Observed Result |
|---|---|
| Successful logon events | 454 |
| Failed logon events | 0 |
| Accounts meeting failure threshold | 0 |
| Successful Remote Desktop logons | 0 |

These findings describe the events returned by the query, not all possible authentication activity on the system.

## 4. Analysis

The majority of the investigation focused on authentication monitoring and identification of potential security indicators.

No repeated authentication failures met the configured threshold.

No successful Remote Desktop logons were observed in the returned events.

The results did not establish unauthorized access, credential compromise, or a brute-force attack.

## 5. Limitations

- Analysis was restricted to locally retained Windows Security events.
- Relevant auditing settings and log retention may affect visibility.
- The script did not correlate failures within short time windows.
- The script did not assess source IP reputation.
- The script did not validate whether successful authentication activity was authorized.
- Microsoft Sentinel was not used for this execution.

## 6. Recommended Improvements

1. Implement five-minute failed authentication windows.
2. Group failures by account and source IP address.
3. Detect failed authentication followed by successful authentication.
4. Export alerts to structured CSV or JSON.
5. Incorporate automated event correlation.
6. Integrate detections with Microsoft Sentinel when telemetry becomes available.

## 7. Conclusion

The Lab 6 detection script successfully processed Windows Security authentication records and produced a structured summary of authentication activity.

The execution demonstrated automated security log collection, detection filtering, and basic alert analysis.

No confirmed security incident was identified.

**Associated Script:** `queries/004-automated-authentication-detection.ps1`

---

**Portfolio Disclosure:** Results were obtained from actual local Windows Security Event Logs. This investigation does not represent live Microsoft Sentinel monitoring.
