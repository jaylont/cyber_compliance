#!/usr/bin/env python3
"""
HTML Report Generator for Compliance Tool
"""

from datetime import datetime

class ReportGenerator:
    def __init__(self, results, system_info):
        self.results = results
        self.system_info = system_info
        
    def generate_html(self, filename='compliance_report.html'):
        """Generate HTML compliance report"""
        
        total = len(self.results['passed']) + len(self.results['failed']) + len(self.results['warnings'])
        passed = len(self.results['passed'])
        failed = len(self.results['failed'])
        warnings = len(self.results['warnings'])
        score = (passed / total * 100) if total > 0 else 0
        
        # Determine status color
        if score >= 90:
            status_color = '#28a745'  # Green
            status_text = 'EXCELLENT'
        elif score >= 75:
            status_color = '#ffc107'  # Yellow
            status_text = 'GOOD'
        elif score >= 50:
            status_color = '#fd7e14'  # Orange
            status_text = 'NEEDS IMPROVEMENT'
        else:
            status_color = '#dc3545'  # Red
            status_text = 'CRITICAL'
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Audit Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }}
        
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .passed {{ color: #28a745; }}
        .failed {{ color: #dc3545; }}
        .warnings {{ color: #ffc107; }}
        
        .score {{
            text-align: center;
            padding: 40px;
            background: white;
        }}
        
        .score-circle {{
            width: 200px;
            height: 200px;
            margin: 0 auto 20px;
            border-radius: 50%;
            background: conic-gradient(
                {status_color} 0deg,
                {status_color} {score * 3.6}deg,
                #e9ecef {score * 3.6}deg,
                #e9ecef 360deg
            );
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }}
        
        .score-circle::before {{
            content: '';
            width: 160px;
            height: 160px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }}
        
        .score-text {{
            position: relative;
            z-index: 1;
            font-size: 3em;
            font-weight: bold;
            color: {status_color};
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 10px 30px;
            background: {status_color};
            color: white;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .section {{
            padding: 30px;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .check-item {{
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        
        .check-item.pass {{
            border-left-color: #28a745;
        }}
        
        .check-item.fail {{
            border-left-color: #dc3545;
        }}
        
        .check-item.warning {{
            border-left-color: #ffc107;
        }}
        
        .check-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .check-name {{
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
        }}
        
        .check-status {{
            padding: 5px 15px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .check-status.pass {{
            background: #d4edda;
            color: #155724;
        }}
        
        .check-status.fail {{
            background: #f8d7da;
            color: #721c24;
        }}
        
        .check-status.warning {{
            background: #fff3cd;
            color: #856404;
        }}
        
        .check-message {{
            color: #666;
            margin: 10px 0;
        }}
        
        .remediation {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 3px solid #667eea;
        }}
        
        .remediation strong {{
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }}
        
        .frameworks {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 10px;
        }}
        
        .framework-tag {{
            background: #e7f3ff;
            color: #0066cc;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Compliance Audit Report</h1>
            <p>System: {self.system_info} | Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Checks</h3>
                <div class="number">{total}</div>
            </div>
            <div class="summary-card">
                <h3>Passed</h3>
                <div class="number passed">✓ {passed}</div>
            </div>
            <div class="summary-card">
                <h3>Failed</h3>
                <div class="number failed">✗ {failed}</div>
            </div>
            <div class="summary-card">
                <h3>Warnings</h3>
                <div class="number warnings">⚠ {warnings}</div>
            </div>
        </div>
        
        <div class="score">
            <div class="score-circle">
                <div class="score-text">{score:.0f}%</div>
            </div>
            <div class="status-badge">{status_text}</div>
        </div>
"""
        
        # Failed checks section
        if failed > 0:
            html += """
        <div class="section">
            <h2>❌ Failed Checks (Action Required)</h2>
"""
            for item in self.results['failed']:
                html += f"""
            <div class="check-item fail">
                <div class="check-header">
                    <div class="check-name">{item['check']}</div>
                    <div class="check-status fail">FAIL</div>
                </div>
                <div class="check-message">{item['message']}</div>
                <div class="remediation">
                    <strong>🔧 Remediation:</strong>
                    {item['remediation']}
                </div>
                <div class="frameworks">
"""
                for fw in item['frameworks']:
                    html += f'                    <span class="framework-tag">{fw}</span>\n'
                
                html += """
                </div>
            </div>
"""
            html += "        </div>\n"
        
        # Passed checks section
        if passed > 0:
            html += """
        <div class="section">
            <h2>✅ Passed Checks</h2>
"""
            for item in self.results['passed']:
                html += f"""
            <div class="check-item pass">
                <div class="check-header">
                    <div class="check-name">{item['check']}</div>
                    <div class="check-status pass">PASS</div>
                </div>
                <div class="check-message">{item['message']}</div>
                <div class="frameworks">
"""
                for fw in item['frameworks']:
                    html += f'                    <span class="framework-tag">{fw}</span>\n'
                
                html += """
                </div>
            </div>
"""
            html += "        </div>\n"
        
        # Warnings section
        if warnings > 0:
            html += """
        <div class="section">
            <h2>⚠️ Warnings</h2>
"""
            for item in self.results['warnings']:
                html += f"""
            <div class="check-item warning">
                <div class="check-header">
                    <div class="check-name">{item['check']}</div>
                    <div class="check-status warning">WARNING</div>
                </div>
                <div class="check-message">{item['message']}</div>
                <div class="frameworks">
"""
                for fw in item['frameworks']:
                    html += f'                    <span class="framework-tag">{fw}</span>\n'
                
                html += """
                </div>
            </div>
"""
            html += "        </div>\n"
        
        # Footer
        html += f"""
        <div class="footer">
            <p>Compliance Automation Tool | Frameworks: CIS, NIST, ISO 27001</p>
            <p>Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html)
        
        print(f"📊 HTML report generated: {filename}")
        return filename