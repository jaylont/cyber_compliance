# Automated Security Compliance Tool

Automated compliance auditing against **CIS Benchmarks**, **NIST 800-53**, and **ISO 27001** with visual reporting and remediation guidance.

## Features

- 10+ automated security checks across 3 frameworks
- HTML dashboard with compliance scoring
- JSON export for automation
- Zero dependencies (Python standard library)
- Cross-platform (Linux, macOS, Windows)

## Quick Start
```bash
git clone https://github.com/jaylont/cyber-compliance.git
cd cyber-compliance
python3 compliance_checker.py
open compliance_report.html
```

## Security Checks

**System Hardening:** Disk encryption, firewall, auto-updates, screen lock  
**Access Control:** Password policy, SSH hardening, user accounts, file permissions  
**Monitoring:** Audit logging, anti-malware

## Sample Output
```
Compliance Score: 70.0%
✓ Passed:     7
✗ Failed:     2
⚠ Warnings:   1

Failed: Firewall not enabled
Fix: Enable in System Preferences > Security
Frameworks: CIS-3.5.1.1, NIST-SC-7, ISO27001-A.13.1.1
```

## Technical Stack

Python 3.8+ | CIS Benchmarks | NIST 800-53 | ISO 27001

## Author

**Jaylon Taylor**  
GitHub: [@jaylont](https://github.com/jaylont) | Email: jaylon.mtaylor@gmail.com

---
