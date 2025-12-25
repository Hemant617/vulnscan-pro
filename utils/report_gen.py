"""
Report Generation Utility
Generate PDF and HTML reports
"""

from datetime import datetime


class ReportGenerator:
    """Generate vulnerability scan reports"""
    
    def __init__(self, scan, vulnerabilities):
        self.scan = scan
        self.vulnerabilities = vulnerabilities
    
    def generate_html_report(self):
        """Generate HTML report"""
        severity_counts = self.count_by_severity()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Scan Report - {self.scan.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
                .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; }}
                .critical {{ background: #fee; border: 2px solid #c00; }}
                .high {{ background: #ffeaa7; border: 2px solid #fdcb6e; }}
                .medium {{ background: #fff3cd; border: 2px solid #ffc107; }}
                .low {{ background: #d4edda; border: 2px solid #28a745; }}
                .vulnerability {{ margin: 20px 0; padding: 15px; border-left: 4px solid; }}
                .vulnerability.critical {{ border-color: #c00; background: #fee; }}
                .vulnerability.high {{ border-color: #ff6b6b; background: #ffe0e0; }}
                .vulnerability.medium {{ border-color: #ffc107; background: #fff3cd; }}
                .vulnerability.low {{ border-color: #28a745; background: #d4edda; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Vulnerability Scan Report</h1>
                <p>Target: {self.scan.target}</p>
                <p>Scan Date: {self.scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Risk Score: {self.scan.risk_score}/100</p>
            </div>
            
            <div class="summary">
                <div class="summary-card critical">
                    <h2>{severity_counts['critical']}</h2>
                    <p>Critical</p>
                </div>
                <div class="summary-card high">
                    <h2>{severity_counts['high']}</h2>
                    <p>High</p>
                </div>
                <div class="summary-card medium">
                    <h2>{severity_counts['medium']}</h2>
                    <p>Medium</p>
                </div>
                <div class="summary-card low">
                    <h2>{severity_counts['low']}</h2>
                    <p>Low</p>
                </div>
            </div>
            
            <h2>Detailed Findings</h2>
        """
        
        for vuln in self.vulnerabilities:
            html += f"""
            <div class="vulnerability {vuln.severity}">
                <h3>{vuln.title}</h3>
                <p><strong>Severity:</strong> {vuln.severity.upper()}</p>
                {f'<p><strong>Port:</strong> {vuln.port}</p>' if vuln.port else ''}
                {f'<p><strong>Service:</strong> {vuln.service}</p>' if vuln.service else ''}
                {f'<p><strong>CVE:</strong> {vuln.cve}</p>' if vuln.cve else ''}
                <p><strong>Description:</strong> {vuln.description}</p>
                <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def count_by_severity(self):
        """Count vulnerabilities by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1
        return counts
