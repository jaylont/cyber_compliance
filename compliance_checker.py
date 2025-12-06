#!/usr/bin/env python3
"""
Compliance Automation Tool
Automated security compliance checking against CIS, NIST, ISO 27001
"""

import os
import sys
import platform
import subprocess
import json
from datetime import datetime
from collections import defaultdict

class ComplianceChecker:
    def __init__(self):
        self.system = platform.system()
        self.results = {
            'passed': [],
            'failed': [],
            'warnings': [],
            'info': []
        }
        self.framework_mapping = {
            'CIS': [],
            'NIST': [],
            'ISO27001': []
        }
        
    def run_command(self, command):
        """Execute system command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1
    
    def check_firewall_enabled(self):
        """CIS 3.5.1.1 - Ensure firewall is enabled"""
        check_name = "Firewall Status"
        frameworks = ['CIS-3.5.1.1', 'NIST-SC-7', 'ISO27001-A.13.1.1']
        
        if self.system == "Linux":
            stdout, stderr, code = self.run_command("sudo ufw status")
            if "Status: active" in stdout or "Status: enabled" in stdout:
                self.log_pass(check_name, "Firewall is enabled", frameworks)
            else:
                self.log_fail(check_name, "Firewall is not enabled", 
                            "Enable firewall: sudo ufw enable", frameworks)
        
        elif self.system == "Darwin":  # macOS
            stdout, stderr, code = self.run_command("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
            if "enabled" in stdout.lower():
                self.log_pass(check_name, "Firewall is enabled", frameworks)
            else:
                self.log_fail(check_name, "Firewall is not enabled",
                            "Enable firewall in System Preferences > Security", frameworks)
    
    def check_password_policy(self):
        """CIS 5.4.1 - Password requirements"""
        check_name = "Password Policy"
        frameworks = ['CIS-5.4.1', 'NIST-IA-5', 'ISO27001-A.9.4.3']
        
        if self.system == "Linux":
            # Check minimum password length
            stdout, stderr, code = self.run_command("grep '^PASS_MIN_LEN' /etc/login.defs")
            if stdout and int(stdout.split()[-1]) >= 14:
                self.log_pass(check_name, "Password minimum length is adequate (≥14)", frameworks)
            else:
                self.log_fail(check_name, "Password minimum length is too short",
                            "Set PASS_MIN_LEN to 14 in /etc/login.defs", frameworks)
        
        elif self.system == "Darwin":
            stdout, stderr, code = self.run_command("pwpolicy -getaccountpolicies")
            if "minChars" in stdout:
                self.log_pass(check_name, "Password policy is configured", frameworks)
            else:
                self.log_warning(check_name, "Cannot verify password policy", frameworks)
    
    def check_ssh_configuration(self):
        """CIS 5.2.4 - SSH configuration hardening"""
        check_name = "SSH Configuration"
        frameworks = ['CIS-5.2.4', 'NIST-AC-17', 'ISO27001-A.13.1.1']
        
        ssh_config = "/etc/ssh/sshd_config"
        
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, 'r') as f:
                    config = f.read()
                
                checks = {
                    'PermitRootLogin no': 'Root login is disabled',
                    'PasswordAuthentication no': 'Password auth is disabled (key-based only)',
                    'X11Forwarding no': 'X11 forwarding is disabled',
                    'MaxAuthTries 4': 'Max auth tries is limited'
                }
                
                passed = 0
                failed = 0
                
                for setting, description in checks.items():
                    if setting.split()[0] in config:
                        passed += 1
                    else:
                        failed += 1
                
                if failed == 0:
                    self.log_pass(check_name, f"All SSH hardening checks passed ({passed}/4)", frameworks)
                else:
                    self.log_fail(check_name, f"SSH configuration needs hardening ({passed}/4 passed)",
                                f"Review {ssh_config} and apply CIS SSH hardening", frameworks)
            except PermissionError:
                self.log_warning(check_name, "Permission denied reading SSH config", frameworks)
        else:
            self.log_info(check_name, "SSH not installed or config not found", frameworks)
    
    def check_automatic_updates(self):
        """CIS 1.8 - Ensure system updates are configured"""
        check_name = "Automatic Updates"
        frameworks = ['CIS-1.8', 'NIST-SI-2', 'ISO27001-A.12.6.1']
        
        if self.system == "Linux":
            stdout, stderr, code = self.run_command("systemctl is-enabled unattended-upgrades")
            if "enabled" in stdout:
                self.log_pass(check_name, "Automatic updates are enabled", frameworks)
            else:
                self.log_fail(check_name, "Automatic updates are not enabled",
                            "Install and enable unattended-upgrades", frameworks)
        
        elif self.system == "Darwin":
            stdout, stderr, code = self.run_command("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled")
            if "1" in stdout:
                self.log_pass(check_name, "Automatic update checking is enabled", frameworks)
            else:
                self.log_fail(check_name, "Automatic updates not configured",
                            "Enable in System Preferences > Software Update", frameworks)
    
    def check_disk_encryption(self):
        """CIS 1.1.1 - Ensure disk encryption is enabled"""
        check_name = "Disk Encryption"
        frameworks = ['CIS-1.1.1', 'NIST-SC-28', 'ISO27001-A.10.1.1']
        
        if self.system == "Darwin":
            stdout, stderr, code = self.run_command("fdesetup status")
            if "FileVault is On" in stdout:
                self.log_pass(check_name, "FileVault disk encryption is enabled", frameworks)
            else:
                self.log_fail(check_name, "Disk encryption is not enabled",
                            "Enable FileVault in System Preferences > Security", frameworks)
        
        elif self.system == "Linux":
            stdout, stderr, code = self.run_command("lsblk -o NAME,FSTYPE | grep crypto_LUKS")
            if "crypto_LUKS" in stdout:
                self.log_pass(check_name, "LUKS disk encryption detected", frameworks)
            else:
                self.log_warning(check_name, "Cannot verify disk encryption", frameworks)
    
    def check_screen_lock(self):
        """CIS 1.5.2 - Ensure screen lock is enabled"""
        check_name = "Screen Lock"
        frameworks = ['CIS-1.5.2', 'NIST-AC-11', 'ISO27001-A.11.2.8']
        
        if self.system == "Darwin":
            stdout, stderr, code = self.run_command("defaults read com.apple.screensaver askForPassword")
            if "1" in stdout:
                self.log_pass(check_name, "Screen lock on sleep is enabled", frameworks)
            else:
                self.log_fail(check_name, "Screen lock not configured",
                            "Enable in System Preferences > Security > Require password", frameworks)
    
    def check_user_accounts(self):
        """CIS 5.4.1.1 - Check for users without password"""
        check_name = "User Account Security"
        frameworks = ['CIS-5.4.1.1', 'NIST-IA-5', 'ISO27001-A.9.2.1']
        
        if self.system == "Linux":
            stdout, stderr, code = self.run_command("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
            if stdout.strip():
                self.log_fail(check_name, f"Users without passwords found: {stdout.strip()}",
                            "Set passwords for all user accounts", frameworks)
            else:
                self.log_pass(check_name, "All users have passwords set", frameworks)
        elif self.system == "Darwin":
            self.log_info(check_name, "User account check not applicable on macOS", frameworks)
    
    def check_file_permissions(self):
        """CIS 6.1.2 - Ensure sensitive file permissions"""
        check_name = "Critical File Permissions"
        frameworks = ['CIS-6.1.2', 'NIST-AC-6', 'ISO27001-A.9.4.1']
        
        critical_files = {
            '/etc/passwd': '644',
            '/etc/group': '644'
        }
        
        issues = []
        for file_path, expected_perms in critical_files.items():
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                actual_perms = oct(stat_info.st_mode)[-3:]
                
                if actual_perms != expected_perms:
                    issues.append(f"{file_path}: {actual_perms} (should be {expected_perms})")
        
        if not issues:
            self.log_pass(check_name, "Critical file permissions are correct", frameworks)
        else:
            self.log_fail(check_name, f"Incorrect permissions: {', '.join(issues)}",
                        "Fix file permissions using chmod", frameworks)
    
    def check_audit_logging(self):
        """CIS 4.1.1.1 - Ensure auditing is enabled"""
        check_name = "Audit Logging"
        frameworks = ['CIS-4.1.1.1', 'NIST-AU-2', 'ISO27001-A.12.4.1']
        
        if self.system == "Linux":
            stdout, stderr, code = self.run_command("systemctl is-enabled auditd")
            if "enabled" in stdout:
                self.log_pass(check_name, "Audit logging (auditd) is enabled", frameworks)
            else:
                self.log_fail(check_name, "Audit logging is not enabled",
                            "Install and enable auditd", frameworks)
        
        elif self.system == "Darwin":
            stdout, stderr, code = self.run_command("sudo launchctl list | grep auditd")
            if stdout:
                self.log_pass(check_name, "Audit logging is enabled", frameworks)
            else:
                self.log_warning(check_name, "Cannot verify audit logging", frameworks)
    
    def check_antivirus(self):
        """NIST-SI-3 - Ensure antivirus is installed"""
        check_name = "Antivirus Protection"
        frameworks = ['NIST-SI-3', 'ISO27001-A.12.2.1']
        
        av_processes = ['clamav', 'sophos', 'xprotect', 'defender']
        
        if self.system == "Linux":
            stdout, stderr, code = self.run_command("ps aux | grep -E 'clam|sophos'")
            if any(av in stdout.lower() for av in av_processes):
                self.log_pass(check_name, "Antivirus software is running", frameworks)
            else:
                self.log_fail(check_name, "No antivirus software detected",
                            "Install ClamAV or commercial AV solution", frameworks)
        
        elif self.system == "Darwin":
            # XProtect is built-in to macOS
            self.log_pass(check_name, "XProtect is built into macOS", frameworks)
    
    def log_pass(self, check_name, message, frameworks):
        """Log a passed check"""
        self.results['passed'].append({
            'check': check_name,
            'status': 'PASS',
            'message': message,
            'frameworks': frameworks,
            'timestamp': datetime.now().isoformat()
        })
        for fw in frameworks:
            self.framework_mapping[fw.split('-')[0]].append(check_name)
    
    def log_fail(self, check_name, message, remediation, frameworks):
        """Log a failed check"""
        self.results['failed'].append({
            'check': check_name,
            'status': 'FAIL',
            'message': message,
            'remediation': remediation,
            'frameworks': frameworks,
            'timestamp': datetime.now().isoformat()
        })
        for fw in frameworks:
            self.framework_mapping[fw.split('-')[0]].append(check_name)
    
    def log_warning(self, check_name, message, frameworks):
        """Log a warning"""
        self.results['warnings'].append({
            'check': check_name,
            'status': 'WARNING',
            'message': message,
            'frameworks': frameworks,
            'timestamp': datetime.now().isoformat()
        })
    
    def log_info(self, check_name, message, frameworks):
        """Log informational message"""
        self.results['info'].append({
            'check': check_name,
            'status': 'INFO',
            'message': message,
            'frameworks': frameworks,
            'timestamp': datetime.now().isoformat()
        })
    
    def run_all_checks(self):
        """Run all compliance checks"""
        print("\n" + "="*60)
        print("COMPLIANCE AUTOMATION TOOL")
        print("="*60)
        print(f"System: {self.system}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        checks = [
            self.check_firewall_enabled,
            self.check_password_policy,
            self.check_ssh_configuration,
            self.check_automatic_updates,
            self.check_disk_encryption,
            self.check_screen_lock,
            self.check_user_accounts,
            self.check_file_permissions,
            self.check_audit_logging,
            self.check_antivirus
        ]
        
        for i, check in enumerate(checks, 1):
            print(f"[{i}/{len(checks)}] Running {check.__name__}...")
            try:
                check()
            except Exception as e:
                print(f"  ERROR: {e}")
        
        print("\n" + "="*60)
        self.print_summary()
    
    def print_summary(self):
        """Print compliance check summary"""
        total = len(self.results['passed']) + len(self.results['failed']) + len(self.results['warnings'])
        passed = len(self.results['passed'])
        failed = len(self.results['failed'])
        warnings = len(self.results['warnings'])
        
        score = (passed / total * 100) if total > 0 else 0
        
        print("COMPLIANCE SUMMARY")
        print("="*60)
        print(f"Total Checks: {total}")
        print(f"✓ Passed:     {passed}")
        print(f"✗ Failed:     {failed}")
        print(f"⚠ Warnings:   {warnings}")
        print(f"\nCompliance Score: {score:.1f}%")
        print("="*60)
        
        # Show failed checks
        if failed > 0:
            print("\n❌ FAILED CHECKS:")
            print("-"*60)
            for item in self.results['failed']:
                print(f"\n• {item['check']}")
                print(f"  Issue: {item['message']}")
                print(f"  Fix: {item['remediation']}")
                print(f"  Frameworks: {', '.join(item['frameworks'])}")
        
        # Framework breakdown
        print("\n📋 FRAMEWORK COVERAGE:")
        print("-"*60)
        for framework, checks in self.framework_mapping.items():
            print(f"{framework}: {len(set(checks))} controls checked")
    
    def export_json(self, filename='compliance_report.json'):
        """Export results to JSON"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'system': self.system,
            'results': self.results,
            'summary': {
                'total': len(self.results['passed']) + len(self.results['failed']) + len(self.results['warnings']),
                'passed': len(self.results['passed']),
                'failed': len(self.results['failed']),
                'warnings': len(self.results['warnings']),
                'score': (len(self.results['passed']) / 
                         (len(self.results['passed']) + len(self.results['failed']) + len(self.results['warnings'])) * 100)
                         if (len(self.results['passed']) + len(self.results['failed']) + len(self.results['warnings'])) > 0 else 0
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 JSON report exported to: {filename}")
    
    def export_html(self, filename='compliance_report.html'):
        """Export results to HTML"""
        from report_generator import ReportGenerator
        
        generator = ReportGenerator(self.results, self.system)
        generator.generate_html(filename)

def main():
    checker = ComplianceChecker()
    checker.run_all_checks()
    checker.export_json()
    checker.export_html()

if __name__ == "__main__":
    main()