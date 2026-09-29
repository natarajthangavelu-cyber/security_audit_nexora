# Audit Checklist (used during the simulated audit)

## Planning
- [ ] Written authorisation and Rules of Engagement signed
- [ ] Scope, IP ranges, exclusions and testing windows agreed
- [ ] Emergency contact and stop-test procedure defined
- [ ] Document request list issued

## Technical review
- [ ] Asset discovery (Nmap) reconciled with CMDB
- [ ] Authenticated vulnerability scan (Nessus/OpenVAS) - internal + external
- [ ] Web app test (OWASP ZAP/Burp) against OWASP Top 10
- [ ] TLS test (testssl.sh)
- [ ] AD review (PingCastle, BloodHound)
- [ ] Cloud review (Prowler/ScoutSuite)
- [ ] Firewall rule-base and segmentation review
- [ ] Backup and restore verification

## Governance
- [ ] Policies reviewed (ISMS, access, backup, IR, BCP, vendor)
- [ ] Interviews completed (IT, HR, Finance, Dev)
- [ ] Phishing simulation completed
- [ ] Log retention checked against CERT-In (180 days)

## Reporting
- [ ] Findings validated, false positives removed
- [ ] CVSS + likelihood x impact scoring done
- [ ] Draft report, factual-accuracy review, closing meeting
- [ ] Follow-up dates scheduled (Day 3, 30, 90, 180, 365)
