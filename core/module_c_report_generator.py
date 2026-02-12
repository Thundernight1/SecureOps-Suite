"""
SecureOps Module C: Report_Generator
Purpose: Generate professional client reports from scanner results
Author: Orchestration Lead Agent
Version: 1.0.0
Security Level: Production-Ready
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from enum import Enum
import hashlib
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats"""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    EXECUTIVE = "executive"


class ReportGenerator:
    """
    Production-grade report generator for penetration testing results.
    Combines Web Scanner and Port Scanner results into professional reports.
    """
    
    def __init__(self, company_name: str = "SecureOps", client_name: str = "Client"):
        """
        Initialize the Report Generator.
        
        Args:
            company_name: Name of the security company
            client_name: Name of the client
        """
        self.company_name = company_name
        self.client_name = client_name
        self.report_id = str(uuid.uuid4())
        self.generation_timestamp = datetime.now().isoformat()
        self.report_data = {
            'report_id': self.report_id,
            'company': company_name,
            'client': client_name,
            'generated_at': self.generation_timestamp,
            'web_scan_results': None,
            'port_scan_results': None,
            'combined_findings': [],
            'risk_summary': {},
            'recommendations': []
        }
    
    def add_web_scan_results(self, web_scan_data: Dict) -> None:
        """
        Add web scanner results to report.
        
        Args:
            web_scan_data: Results from Web_Scanner module
        """
        if not isinstance(web_scan_data, dict):
            logger.error("Invalid web scan data format")
            raise ValueError("Web scan data must be a dictionary")
        
        self.report_data['web_scan_results'] = web_scan_data
        logger.info("Web scan results added to report")
    
    def add_port_scan_results(self, port_scan_data: Dict) -> None:
        """
        Add port scanner results to report.
        
        Args:
            port_scan_data: Results from Port_Scanner module
        """
        if not isinstance(port_scan_data, dict):
            logger.error("Invalid port scan data format")
            raise ValueError("Port scan data must be a dictionary")
        
        self.report_data['port_scan_results'] = port_scan_data
        logger.info("Port scan results added to report")
    
    def _extract_web_findings(self) -> List[Dict]:
        """
        Extract key findings from web scan results.
        
        Returns:
            List of web security findings
        """
        findings = []
        web_data = self.report_data['web_scan_results']
        
        if not web_data:
            return findings
        
        # Extract missing security headers
        if 'security_headers' in web_data and 'missing_headers' in web_data['security_headers']:
            for header in web_data['security_headers']['missing_headers']:
                findings.append({
                    'type': 'Missing Security Header',
                    'component': 'Web Application',
                    'finding': header['header'],
                    'description': header['recommendation'],
                    'severity': header.get('severity', 'medium'),
                    'impact': f"Application lacks {header['header']} protection",
                    'remediation': f"Implement {header['header']} in HTTP response headers"
                })
        
        # Extract XSS vulnerabilities
        if 'xss_vulnerabilities' in web_data:
            for vuln in web_data['xss_vulnerabilities']:
                findings.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'component': 'Web Application',
                    'finding': f"XSS in {vuln.get('parameter', 'unknown')} parameter",
                    'description': f"Reflected XSS vulnerability detected via {vuln.get('method', 'GET')} method",
                    'severity': vuln.get('severity', 'high'),
                    'impact': 'Attackers can inject malicious scripts to steal user data or perform actions',
                    'remediation': 'Implement input validation, output encoding, and Content Security Policy',
                    'affected_url': vuln.get('url', 'N/A')
                })
        
        return findings
    
    def _extract_port_findings(self) -> List[Dict]:
        """
        Extract key findings from port scan results.
        
        Returns:
            List of port security findings
        """
        findings = []
        port_data = self.report_data['port_scan_results']
        
        if not port_data:
            return findings
        
        # Extract open ports
        if 'open_ports' in port_data:
            for port_info in port_data['open_ports']:
                severity = port_info.get('severity', 'medium')
                
                findings.append({
                    'type': 'Open Port',
                    'component': 'Network Infrastructure',
                    'finding': f"Port {port_info['port']} ({port_info['service']}) is open",
                    'description': f"{port_info['service_description']} service is accessible",
                    'severity': severity,
                    'impact': self._get_port_impact(port_info['port']),
                    'remediation': self._get_port_remediation(port_info['port']),
                    'port_number': port_info['port'],
                    'service': port_info['service']
                })
        
        return findings
    
    def _get_port_impact(self, port: int) -> str:
        """
        Get impact description for open port.
        
        Args:
            port: Port number
            
        Returns:
            Impact description
        """
        port_impacts = {
            22: "SSH access could allow unauthorized remote access to systems",
            23: "Telnet is unencrypted and allows remote access",
            3389: "RDP access could allow unauthorized remote desktop connections",
            3306: "MySQL database is exposed to network attacks",
            5432: "PostgreSQL database is exposed to network attacks",
            6379: "Redis cache is exposed without authentication",
            27017: "MongoDB database is exposed to network attacks",
            9200: "Elasticsearch is exposed to data theft and manipulation",
            445: "SMB is exposed to ransomware and lateral movement attacks",
            80: "HTTP traffic is unencrypted and vulnerable to interception",
            443: "HTTPS port open - verify certificate validity and TLS version"
        }
        
        return port_impacts.get(port, "Open port could be exploited for unauthorized access")
    
    def _get_port_remediation(self, port: int) -> str:
        """
        Get remediation steps for open port.
        
        Args:
            port: Port number
            
        Returns:
            Remediation steps
        """
        port_remediations = {
            22: "Restrict SSH access via firewall, use key-based authentication, disable root login",
            23: "Disable Telnet, use SSH instead",
            3389: "Restrict RDP to VPN, use Network Level Authentication, disable if not needed",
            3306: "Move MySQL to private network, implement firewall rules, require authentication",
            5432: "Move PostgreSQL to private network, implement firewall rules, require authentication",
            6379: "Implement Redis authentication, move to private network, use firewall rules",
            27017: "Implement MongoDB authentication, move to private network, use firewall rules",
            9200: "Restrict Elasticsearch access, implement authentication, use firewall rules",
            445: "Disable SMB if not needed, restrict access via firewall, keep systems patched",
            80: "Redirect HTTP to HTTPS, implement HSTS headers",
            443: "Verify SSL/TLS certificate, use TLS 1.2 or higher, implement HSTS"
        }
        
        return port_remediations.get(port, "Restrict access via firewall, implement authentication")
    
    def generate_combined_findings(self) -> List[Dict]:
        """
        Generate combined findings from all scan results.
        
        Returns:
            List of all findings
        """
        findings = []
        
        # Extract web findings
        findings.extend(self._extract_web_findings())
        
        # Extract port findings
        findings.extend(self._extract_port_findings())
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
        
        self.report_data['combined_findings'] = findings
        logger.info(f"Generated {len(findings)} combined findings")
        
        return findings
    
    def generate_risk_summary(self) -> Dict:
        """
        Generate risk summary from findings.
        
        Returns:
            Risk summary dictionary
        """
        findings = self.report_data['combined_findings']
        
        summary = {
            'total_findings': len(findings),
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'overall_risk_level': 'low',
            'risk_score': 0.0
        }
        
        # Count findings by severity
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity == 'critical':
                summary['critical_count'] += 1
            elif severity == 'high':
                summary['high_count'] += 1
            elif severity == 'medium':
                summary['medium_count'] += 1
            elif severity == 'low':
                summary['low_count'] += 1
        
        # Calculate risk score (0-100)
        summary['risk_score'] = (
            summary['critical_count'] * 25 +
            summary['high_count'] * 15 +
            summary['medium_count'] * 5 +
            summary['low_count'] * 1
        )
        summary['risk_score'] = min(summary['risk_score'], 100)
        
        # Determine overall risk level
        if summary['critical_count'] > 0:
            summary['overall_risk_level'] = 'critical'
        elif summary['high_count'] > 0:
            summary['overall_risk_level'] = 'high'
        elif summary['medium_count'] > 0:
            summary['overall_risk_level'] = 'medium'
        else:
            summary['overall_risk_level'] = 'low'
        
        self.report_data['risk_summary'] = summary
        logger.info(f"Risk summary generated: {summary['overall_risk_level']} risk")
        
        return summary
    
    def generate_recommendations(self) -> List[str]:
        """
        Generate actionable recommendations based on findings.
        
        Returns:
            List of recommendations
        """
        recommendations = []
        findings = self.report_data['combined_findings']
        risk_summary = self.report_data['risk_summary']
        
        # Priority-based recommendations
        if risk_summary['critical_count'] > 0:
            recommendations.append(
                "IMMEDIATE ACTION REQUIRED: Address all critical findings within 24-48 hours"
            )
        
        if risk_summary['high_count'] > 0:
            recommendations.append(
                "HIGH PRIORITY: Remediate high-severity findings within 1 week"
            )
        
        # Specific recommendations based on findings
        finding_types = set(f.get('type') for f in findings)
        
        if 'Cross-Site Scripting (XSS)' in finding_types:
            recommendations.append(
                "Implement comprehensive input validation and output encoding across all web applications"
            )
            recommendations.append(
                "Deploy Content Security Policy (CSP) headers to mitigate XSS attacks"
            )
        
        if 'Missing Security Header' in finding_types:
            recommendations.append(
                "Implement all recommended security headers in HTTP responses"
            )
        
        if 'Open Port' in finding_types:
            recommendations.append(
                "Review firewall rules and restrict access to unnecessary ports"
            )
            recommendations.append(
                "Implement network segmentation to isolate critical services"
            )
        
        # General recommendations
        recommendations.append(
            "Conduct regular security assessments (quarterly recommended)"
        )
        recommendations.append(
            "Implement a vulnerability management program with regular patching"
        )
        recommendations.append(
            "Provide security awareness training to development and operations teams"
        )
        recommendations.append(
            "Establish incident response procedures and conduct regular drills"
        )
        
        self.report_data['recommendations'] = recommendations
        logger.info(f"Generated {len(recommendations)} recommendations")
        
        return recommendations
    
    def generate_report(self, format: ReportFormat = ReportFormat.JSON) -> str:
        """
        Generate complete report in specified format.
        
        Args:
            format: Report format (JSON, HTML, MARKDOWN, EXECUTIVE)
            
        Returns:
            Formatted report string
        """
        # Generate all components
        self.generate_combined_findings()
        self.generate_risk_summary()
        self.generate_recommendations()
        
        if format == ReportFormat.JSON:
            return self._generate_json_report()
        elif format == ReportFormat.HTML:
            return self._generate_html_report()
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report()
        elif format == ReportFormat.EXECUTIVE:
            return self._generate_executive_report()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json_report(self) -> str:
        """Generate JSON format report."""
        return json.dumps(self.report_data, indent=2)
    
    def _generate_html_report(self) -> str:
        """Generate HTML format report."""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("<meta charset='UTF-8'>")
        html.append("<title>Security Assessment Report</title>")
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }")
        html.append(".header { background-color: #1a1a1a; color: white; padding: 20px; border-radius: 5px; }")
        html.append(".section { background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")
        html.append(".critical { color: #d32f2f; font-weight: bold; }")
        html.append(".high { color: #f57c00; font-weight: bold; }")
        html.append(".medium { color: #fbc02d; font-weight: bold; }")
        html.append(".low { color: #388e3c; font-weight: bold; }")
        html.append("table { width: 100%; border-collapse: collapse; margin: 10px 0; }")
        html.append("th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }")
        html.append("th { background-color: #f0f0f0; font-weight: bold; }")
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")
        
        # Header
        html.append("<div class='header'>")
        html.append(f"<h1>Security Assessment Report</h1>")
        html.append(f"<p>Client: {self.report_data['client']}</p>")
        html.append(f"<p>Report ID: {self.report_data['report_id']}</p>")
        html.append(f"<p>Generated: {self.report_data['generated_at']}</p>")
        html.append("</div>")
        
        # Risk Summary
        risk = self.report_data['risk_summary']
        html.append("<div class='section'>")
        html.append("<h2>Risk Summary</h2>")
        html.append(f"<p>Overall Risk Level: <span class='{risk['overall_risk_level']}'>{risk['overall_risk_level'].upper()}</span></p>")
        html.append(f"<p>Risk Score: {risk['risk_score']}/100</p>")
        html.append(f"<p>Total Findings: {risk['total_findings']}</p>")
        html.append(f"<p>Critical: {risk['critical_count']} | High: {risk['high_count']} | Medium: {risk['medium_count']} | Low: {risk['low_count']}</p>")
        html.append("</div>")
        
        # Findings
        html.append("<div class='section'>")
        html.append("<h2>Detailed Findings</h2>")
        html.append("<table>")
        html.append("<tr><th>Type</th><th>Component</th><th>Finding</th><th>Severity</th><th>Remediation</th></tr>")
        
        for finding in self.report_data['combined_findings']:
            severity_class = finding.get('severity', 'low')
            html.append("<tr>")
            html.append(f"<td>{finding.get('type', 'N/A')}</td>")
            html.append(f"<td>{finding.get('component', 'N/A')}</td>")
            html.append(f"<td>{finding.get('finding', 'N/A')}</td>")
            html.append(f"<td><span class='{severity_class}'>{finding.get('severity', 'N/A').upper()}</span></td>")
            html.append(f"<td>{finding.get('remediation', 'N/A')}</td>")
            html.append("</tr>")
        
        html.append("</table>")
        html.append("</div>")
        
        # Recommendations
        html.append("<div class='section'>")
        html.append("<h2>Recommendations</h2>")
        html.append("<ol>")
        for rec in self.report_data['recommendations']:
            html.append(f"<li>{rec}</li>")
        html.append("</ol>")
        html.append("</div>")
        
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def _generate_markdown_report(self) -> str:
        """Generate Markdown format report."""
        md = []
        md.append("# Security Assessment Report")
        md.append("")
        md.append(f"**Client:** {self.report_data['client']}")
        md.append(f"**Report ID:** {self.report_data['report_id']}")
        md.append(f"**Generated:** {self.report_data['generated_at']}")
        md.append("")
        
        # Risk Summary
        risk = self.report_data['risk_summary']
        md.append("## Risk Summary")
        md.append("")
        md.append(f"- **Overall Risk Level:** {risk['overall_risk_level'].upper()}")
        md.append(f"- **Risk Score:** {risk['risk_score']}/100")
        md.append(f"- **Total Findings:** {risk['total_findings']}")
        md.append(f"- **Critical:** {risk['critical_count']} | **High:** {risk['high_count']} | **Medium:** {risk['medium_count']} | **Low:** {risk['low_count']}")
        md.append("")
        
        # Findings
        md.append("## Detailed Findings")
        md.append("")
        for i, finding in enumerate(self.report_data['combined_findings'], 1):
            md.append(f"### {i}. {finding.get('type', 'N/A')}")
            md.append(f"- **Component:** {finding.get('component', 'N/A')}")
            md.append(f"- **Finding:** {finding.get('finding', 'N/A')}")
            md.append(f"- **Severity:** {finding.get('severity', 'N/A').upper()}")
            md.append(f"- **Description:** {finding.get('description', 'N/A')}")
            md.append(f"- **Impact:** {finding.get('impact', 'N/A')}")
            md.append(f"- **Remediation:** {finding.get('remediation', 'N/A')}")
            md.append("")
        
        # Recommendations
        md.append("## Recommendations")
        md.append("")
        for i, rec in enumerate(self.report_data['recommendations'], 1):
            md.append(f"{i}. {rec}")
        md.append("")
        
        return "\n".join(md)
    
    def _generate_executive_report(self) -> str:
        """Generate executive summary report."""
        exec_report = []
        exec_report.append("=" * 70)
        exec_report.append("EXECUTIVE SUMMARY - SECURITY ASSESSMENT REPORT")
        exec_report.append("=" * 70)
        exec_report.append("")
        exec_report.append(f"Client: {self.report_data['client']}")
        exec_report.append(f"Assessment Date: {self.report_data['generated_at']}")
        exec_report.append(f"Report ID: {self.report_data['report_id']}")
        exec_report.append("")
        
        risk = self.report_data['risk_summary']
        exec_report.append("RISK ASSESSMENT")
        exec_report.append("-" * 70)
        exec_report.append(f"Overall Risk Level: {risk['overall_risk_level'].upper()}")
        exec_report.append(f"Risk Score: {risk['risk_score']}/100")
        exec_report.append("")
        exec_report.append("Findings Summary:")
        exec_report.append(f"  - Critical Issues: {risk['critical_count']}")
        exec_report.append(f"  - High Priority Issues: {risk['high_count']}")
        exec_report.append(f"  - Medium Priority Issues: {risk['medium_count']}")
        exec_report.append(f"  - Low Priority Issues: {risk['low_count']}")
        exec_report.append("")
        
        exec_report.append("KEY FINDINGS")
        exec_report.append("-" * 70)
        
        # Show top critical findings
        critical_findings = [f for f in self.report_data['combined_findings'] if f.get('severity') == 'critical']
        if critical_findings:
            exec_report.append("CRITICAL ISSUES (Immediate Action Required):")
            for finding in critical_findings[:5]:
                exec_report.append(f"  • {finding.get('finding', 'N/A')}")
        
        exec_report.append("")
        exec_report.append("RECOMMENDATIONS")
        exec_report.append("-" * 70)
        for i, rec in enumerate(self.report_data['recommendations'][:5], 1):
            exec_report.append(f"{i}. {rec}")
        
        exec_report.append("")
        exec_report.append("=" * 70)
        
        return "\n".join(exec_report)


# Example usage
if __name__ == "__main__":
    # Create report generator
    generator = ReportGenerator(company_name="SecureOps", client_name="Seattle Tech Corp")
    
    # Example web scan results
    web_results = {
        'target_url': 'https://example.com',
        'scan_status': 'completed',
        'security_headers': {
            'missing_headers': [
                {'header': 'X-Frame-Options', 'recommendation': 'Add X-Frame-Options header', 'severity': 'medium'}
            ]
        },
        'xss_vulnerabilities': [
            {'type': 'Reflected XSS', 'parameter': 'search', 'severity': 'high', 'url': 'https://example.com?search=test'}
        ]
    }
    
    # Example port scan results
    port_results = {
        'target_ip': '192.168.1.1',
        'scan_status': 'completed',
        'open_ports': [
            {'port': 22, 'service': 'SSH', 'service_description': 'Secure Shell', 'severity': 'critical'},
            {'port': 80, 'service': 'HTTP', 'service_description': 'Hypertext Transfer Protocol', 'severity': 'high'}
        ]
    }
    
    # Add results to generator
    generator.add_web_scan_results(web_results)
    generator.add_port_scan_results(port_results)
    
    # Generate reports in different formats
    print("JSON Report:")
    print(generator.generate_report(ReportFormat.JSON))
    print("\n\nMarkdown Report:")
    print(generator.generate_report(ReportFormat.MARKDOWN))
    print("\n\nExecutive Report:")
    print(generator.generate_report(ReportFormat.EXECUTIVE))
