# Microsoft Sentinel SOC Lab | Python & PowerShell Threat Detection

Hands-on cybersecurity portfolio demonstrating Windows Security Event analysis, automated threat detection, authentication investigations, and Security Operations Center (SOC) workflows.

**Technologies:** Python 3, PowerShell, Windows Event Logs, KQL, Microsoft Azure, Microsoft Sentinel, GitHub

**Certification:** CompTIA Security+ (SY0-701)

## Project Overview

This project demonstrates practical cybersecurity monitoring and incident investigation using local Windows Security Event Logs and simulated authentication telemetry.

The lab combines manual security investigations with Python and PowerShell automation to identify potentially suspicious authentication behavior.

An Azure Log Analytics workspace was also configured, and KQL query execution was verified. Live Windows Security Event ingestion into Microsoft Sentinel remains a future integration goal.

## Key Capabilities

- Windows successful logon analysis using Event ID 4624
- Failed authentication detection using Event ID 4625
- Logon session correlation using Event ID 4634
- Brute-force authentication pattern detection
- Failed-login-followed-by-successful-login detection
- Remote Desktop authentication review using Logon Type 10
- Automated detection reporting
- Unit testing for Python security detection logic
- SOC investigation documentation

## Python Threat Detection Results

The Python SOC detection engine was executed locally against eight simulated authentication records.

| Detection | Severity | Result |
|---|---|---|
| Brute-force pattern | High | Detected |
| Failed logins followed by success | High | Detected |
| Remote Desktop logon review | Medium | Detected |

**Execution summary:** 8 records analyzed; 3 findings generated.

The sample IP addresses use documentation-only address ranges. These findings are simulated and do not represent confirmed attacks.

## Real Windows Authentication Investigation

Windows PowerShell was used to investigate actual local Windows Security Events.

A seven-day authentication detection run returned:

- 454 successful logon events (4624)
- No failed logon events (4625) returned
- No successful Remote Desktop logons (Logon Type 10) returned

A separate investigation correlated two interactive logon sessions with their matching logoff records using Windows Logon IDs.

These investigations demonstrated authentication event analysis, log correlation, and evidence-based security triage.

## Microsoft Azure and Sentinel

Configured resources:

- Azure resource group: `rg-soc-lab`
- Log Analytics workspace: `law-soc-lab-2026`
- Region: East US
- Microsoft Sentinel environment

Successfully executed a KQL test query:

```kql
print Message = "SOC Lab Connected", TestTime = now()
```

The Azure query engine returned a successful result.

**Limitation:** Live Windows Security Event ingestion was not established. Python and PowerShell analyses were executed locally.

## Running the Python Detection Engine

From the Python project directory:

```powershell
python soc_detector.py --input sample-data/simulated_auth_events.json --output output
```

Run automated tests:

```powershell
python -m unittest discover -s tests -v
```

## SOC Skills Demonstrated

- Security event monitoring
- Authentication log analysis
- Threat detection engineering
- Python security automation
- PowerShell scripting
- Incident investigation
- Event correlation
- Alert triage
- Kusto Query Language (KQL)
- Security documentation
- Automated software testing

## Future Enhancements

- Live Azure Monitor Agent integration
- Microsoft Sentinel scheduled analytics rules
- Expanded authentication anomaly detection
- SIEM dashboards and workbooks
- Additional threat simulation scenarios
- MITRE ATT&CK technique mapping

## Project Purpose

This project was developed to demonstrate practical SOC analyst, cybersecurity analyst, and security engineering skills through hands-on implementation, testing, and investigation.

The project distinguishes real Windows authentication investigations from simulated Python detection scenarios to maintain accurate, evidence-based reporting.# Microsoft-Sentinel-SOC-Lab
Hands-on SOC portfolio demonstrating Microsoft Sentinel, KQL threat detection, security alert triage, and incident response. 
