# Cyber Security Audit and Vulnerability Assessment – Nexora Financial Services (Simulated)

Week 5 final task: a simulated cyber security audit of a fictitious 450-employee lender, covering
planning, methodology, data collection, findings, risk assessment, prioritised recommendations and a follow-up plan.

> **Disclaimer:** Nexora is fictitious. All systems, IPs, logs and results are simulated for education. No real system was tested.

## Repository structure
| Path | Description |
|---|---|
| `report/Cyber_Security_Audit_Report.docx` | Full audit report (executive summary, methodology, 14 findings, risk matrix, roadmap) |
| `scripts/log_analyzer.py` | Python tool that detects password-spray / brute-force patterns in auth logs |
| `evidence/` | Simulated authentication and firewall log extracts |
| `data/risk_register.csv` | Risk register (likelihood x impact scoring) |
| `data/remediation_tracker.csv` | Remediation tracker with owners and due dates |
| `docs/audit_checklist.md` | Checklist used during the audit |

## Summary of results
Critical **3** | High **7** | Medium **3** | Low **1** | Total **14** – overall rating: **High risk**.

## Run the log analyser
```bash
python scripts/log_analyzer.py evidence/sample_auth.log --csv data/log_findings.csv
```
Requires Python 3.8+ and no third-party packages.

## Standards used
ISO/IEC 27001:2022, NIST CSF 2.0, CIS Controls v8, NIST SP 800-115 / 800-30, OWASP Top 10, MITRE ATT&CK, CVSS v3.1, CERT-In Directions, DPDP Act 2023.

