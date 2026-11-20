# SOC Incident Report 001 — Suspected Brute-Force Authentication

**Project:** Microsoft Sentinel SOC Lab  
**Platform:** Microsoft Sentinel / Microsoft Defender  
**Investigation type:** Authentication anomaly detection  
**Severity:** Medium (simulated classification)  
**Status:** Investigation completed — simulated scenario  
**Detection:** 001-brute-force-detection.kql

## 1. Executive Summary

A KQL detection query was used to analyze simulated authentication events for repeated failed login attempts.

The analysis identified six failed authentication attempts against the `admin` account originating from the same source IP address within a five-minute interval.

This pattern is consistent with potential password guessing or brute-force behavior. However, the sample data alone does not establish that an actual attack occurred.

## 2. Evidence Collected

| Evidence | Finding |
|---|---|
| Target account | admin |
| Source IP address | 203.0.113.50 |
| Failed login attempts | 6 |
| First attempt | November 19, 2026, 14:00 |
| Last attempt | November 19, 2026, 14:05 |
| Detection threshold | 5 or more failures |
| Data source | Synthetic KQL datatable |

The source IP address is reserved for documentation and testing.

## 3. Detection Methodology

The detection query used Kusto Query Language (KQL) to:

1. Create a simulated authentication-event dataset.
2. Filter events with a `Failed` result.
3. Group events by account and source IP address.
4. Count the failed authentication attempts.
5. Return combinations with five or more failures.

The query successfully identified the `admin` account as meeting the configured threshold based on the sample data.

## 4. Investigation Findings

**Finding 1 — Repeated authentication failures**

Six failed login attempts were associated with the same account and source IP address.

**Finding 2 — Concentrated activity**

The failed attempts occurred within a five-minute interval.

**Finding 3 — No confirmed account compromise**

The simulated dataset does not show a successful login for the targeted `admin` account.

**Finding 4 — Additional investigation required**

In a production environment, the analyst would examine surrounding authentication activity, account history, device context, and available threat intelligence before confirming malicious intent.

## 5. Recommended Response Actions

If this pattern were observed in a real environment:

1. Review the affected account's authentication history.
2. Check whether any successful logins followed the failures.
3. Verify multifactor authentication status.
4. Investigate source IP reputation and related activity.
5. Contact the account owner through an approved process if necessary.
6. Escalate or contain the activity according to the organization's incident response procedures.

## 6. MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** T1110 — Brute Force

This mapping describes a possible attack technique associated with the observed pattern, not a confirmed attack.

## 7. Conclusion

The simulated investigation demonstrated the use of KQL for authentication-event filtering, aggregation, and threshold-based anomaly detection.

The activity was classified as a potential brute-force pattern requiring further investigation in a real SOC environment.

**Lab outcome:** Detection logic documented; no real-world compromise established.

---

**Portfolio note:** This report is based on synthetic security data created for educational and demonstration purposes. It is not a production security incident.
