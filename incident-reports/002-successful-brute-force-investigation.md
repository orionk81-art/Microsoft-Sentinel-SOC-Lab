# SOC Incident Report 002 — Possible Successful Brute-Force Authentication

**Project:** Microsoft Sentinel SOC Lab  
**Platform:** Microsoft Defender Advanced Hunting / KQL  
**Investigation date:** November 20, 2026  
**Classification:** Simulated security investigation  
**Severity:** High (lab-assigned, not a production alert)  
**Status:** Detection validated against synthetic events; no real incident confirmed  
**Detection rule:** `queries/002-failed-then-successful-login.kql`

---

## 1. Executive Summary

A Kusto Query Language (KQL) correlation query was executed against a synthetic authentication dataset to identify accounts experiencing five or more failed login attempts followed by a successful login from the same source IP address within ten minutes of the final failure.

The query identified six failed login attempts targeting the `admin` account from `203.0.113.50`, followed by a successful authentication one minute after the final failed attempt.

This sequence is consistent with possible password guessing or brute-force activity. Although the successful authentication raises concern, the synthetic data does not establish an actual account compromise.

## 2. Investigation Scope

**Objective:** Identify suspicious authentication sequences in which repeated failed login attempts precede a successful login.

**Environment:** Microsoft Defender Advanced Hunting.

**Data source:** Synthetic authentication records created with the KQL `datatable()` function.

**Detection criteria:**
- At least five failed authentication attempts associated with the same account and source IP address.
- A successful authentication occurring after the last failure.
- The successful authentication must occur within ten minutes of the last failed attempt.

## 3. Evidence and Timeline

| Time (UTC, simulated) | Account | Source IP | Event |
|---|---|---|---|
| 14:00 | admin | 203.0.113.50 | Failed login |
| 14:01 | admin | 203.0.113.50 | Failed login |
| 14:02 | admin | 203.0.113.50 | Failed login |
| 14:03 | admin | 203.0.113.50 | Failed login |
| 14:04 | admin | 203.0.113.50 | Failed login |
| 14:05 | admin | 203.0.113.50 | Failed login |
| 14:06 | admin | 203.0.113.50 | Successful login |

**Event date:** November 19, 2026 (synthetic timestamps).

**Total failed attempts:** 6  
**Time between final failure and success:** 1 minute  
**Correlation window:** 10 minutes

The IP address `203.0.113.50` belongs to a documentation-only address range and does not identify a real attacker.

## 4. Detection Methodology

The KQL query separated failed and successful authentication records into two logical datasets.

The query then:

1. Counted failed attempts by account and source IP address.
2. Identified account/IP combinations meeting the threshold of five or more failures.
3. Joined the failure dataset with successful authentication events using the account and IP address.
4. Verified that the successful login occurred after the final failure and within the configured ten-minute window.
5. Returned the matched account, source IP, failure count, event timestamps, and a descriptive alert label.

The query returned one matching account: `admin`.

A second simulated account, `jdoe`, did not meet the failure threshold and was excluded.

## 5. Investigation Findings

### Finding 1 — Repeated authentication failures

Six consecutive failed login attempts were associated with the `admin` account and one source IP address.

### Finding 2 — Successful authentication following failures

A successful login occurred one minute after the final failure, satisfying the detection's correlation criteria.

### Finding 3 — Potential credential compromise

The sequence warrants investigation because it may indicate that an unauthorized party successfully guessed or obtained a password.

However, a successful login following failures can also occur during legitimate user activity. The observed sequence alone cannot establish malicious intent or unauthorized access.

### Finding 4 — No production incident confirmed

The investigation used synthetic data. No actual Microsoft Entra ID compromise, production alert, or malicious session was established.

## 6. MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** T1110 — Brute Force

The mapping identifies a possible attack technique associated with repeated authentication failures. It does not confirm that the technique occurred in a real environment.

## 7. Recommended Incident Response

If equivalent activity were observed in a production environment, the SOC analyst should:

1. Review the affected account's complete sign-in history and authentication details.
2. Determine whether the successful login originated from a recognized device or location.
3. Examine multifactor authentication status and relevant conditional access results.
4. Investigate other accounts accessed from the same source IP address.
5. Review any available post-authentication activity for suspicious actions.
6. Escalate the case according to the organization's incident response procedures.
7. If unauthorized access is confirmed or strongly suspected, coordinate appropriate containment, such as session revocation and credential reset, with authorized personnel.

## 8. Limitations and False Positives

This lab uses a small, fixed dataset and does not include real-world identity telemetry, device information, geolocation, MFA results, or behavioral baselines.

The detection can flag legitimate password-entry mistakes followed by a successful login.

It also aggregates failures by account and IP without limiting the failure aggregation to a fixed time window. A production implementation should add bounded failure windows, ingestion-time considerations, and additional context before use as a scheduled analytics rule.

## 9. Conclusion

The simulated investigation successfully demonstrated how KQL can correlate repeated authentication failures with a subsequent successful login.

The exercise demonstrated foundational SOC capabilities in detection engineering, event correlation, investigation documentation, and incident response planning.

**Final disposition:** Simulated suspicious authentication sequence detected; no real compromise confirmed.

---

**Portfolio disclaimer:** This report documents a controlled educational exercise using synthetic events. It does not represent an actual security incident or a deployed production analytics rule.
