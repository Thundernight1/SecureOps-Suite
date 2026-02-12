"""
SecureOps Module B: Port_Scanner
Purpose: Scan critical ports on target systems for security assessment
Author: Orchestration Lead Agent
Version: 1.0.0
Security Level: Production-Ready
"""

import socket
import threading
import logging
import json
from typing import Dict, List, Tuple
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PortScanner:
    """
    Production-grade port scanner for security assessment.
    Scans critical ports with proper error handling and timeouts.
    """
    
    # Critical ports for security assessment
    CRITICAL_PORTS = {
        20: {'name': 'FTP-DATA', 'service': 'File Transfer Protocol Data', 'severity': 'medium'},
        21: {'name': 'FTP', 'service': 'File Transfer Protocol', 'severity': 'high'},
        22: {'name': 'SSH', 'service': 'Secure Shell', 'severity': 'critical'},
        23: {'name': 'TELNET', 'service': 'Telnet', 'severity': 'critical'},
        25: {'name': 'SMTP', 'service': 'Simple Mail Transfer Protocol', 'severity': 'medium'},
        53: {'name': 'DNS', 'service': 'Domain Name System', 'severity': 'medium'},
        80: {'name': 'HTTP', 'service': 'Hypertext Transfer Protocol', 'severity': 'high'},
        110: {'name': 'POP3', 'service': 'Post Office Protocol', 'severity': 'medium'},
        143: {'name': 'IMAP', 'service': 'Internet Message Access Protocol', 'severity': 'medium'},
        443: {'name': 'HTTPS', 'service': 'HTTP Secure', 'severity': 'high'},
        445: {'name': 'SMB', 'service': 'Server Message Block', 'severity': 'critical'},
        3306: {'name': 'MySQL', 'service': 'MySQL Database', 'severity': 'critical'},
        3389: {'name': 'RDP', 'service': 'Remote Desktop Protocol', 'severity': 'critical'},
        5432: {'name': 'PostgreSQL', 'service': 'PostgreSQL Database', 'severity': 'critical'},
        5984: {'name': 'CouchDB', 'service': 'CouchDB Database', 'severity': 'high'},
        6379: {'name': 'Redis', 'service': 'Redis Cache', 'severity': 'critical'},
        8080: {'name': 'HTTP-ALT', 'service': 'HTTP Alternate', 'severity': 'high'},
        8443: {'name': 'HTTPS-ALT', 'service': 'HTTPS Alternate', 'severity': 'high'},
        9200: {'name': 'Elasticsearch', 'service': 'Elasticsearch', 'severity': 'critical'},
        27017: {'name': 'MongoDB', 'service': 'MongoDB Database', 'severity': 'critical'},
    }
    
    def __init__(self, timeout: int = 3, max_threads: int = 20):
        """
        Initialize the Port Scanner.
        
        Args:
            timeout: Socket timeout in seconds
            max_threads: Maximum concurrent threads for scanning
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = {
            'scan_timestamp': datetime.now().isoformat(),
            'target_ip': None,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_status': 'pending',
            'scan_duration': 0,
            'ports_scanned': 0
        }
        self.lock = threading.Lock()
    
    def validate_ip(self, ip_address: str) -> Tuple[bool, str]:
        """
        Validate IP address format.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            Tuple of (is_valid, normalized_ip)
        """
        try:
            # Try to parse as IP address
            parsed_ip = ipaddress.ip_address(ip_address)
            return True, str(parsed_ip)
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return False, f"Invalid IP address format: {ip_address}"
    
    def scan_port(self, ip_address: str, port: int) -> Dict:
        """
        Scan a single port on target IP.
        
        Args:
            ip_address: Target IP address
            port: Port number to scan
            
        Returns:
            Dictionary containing port scan result
        """
        result = {
            'port': port,
            'status': 'unknown',
            'service': self.CRITICAL_PORTS.get(port, {}).get('name', 'Unknown'),
            'service_description': self.CRITICAL_PORTS.get(port, {}).get('service', 'Unknown'),
            'severity': self.CRITICAL_PORTS.get(port, {}).get('severity', 'low'),
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            connection_result = sock.connect_ex((ip_address, port))
            
            if connection_result == 0:
                result['status'] = 'open'
                logger.info(f"Port {port} is OPEN on {ip_address}")
                
                # Try to identify service
                try:
                    service_name = socket.getservbyport(port)
                    result['service'] = service_name
                except OSError:
                    pass
                
            else:
                result['status'] = 'closed'
                logger.debug(f"Port {port} is CLOSED on {ip_address}")
            
            sock.close()
            
        except socket.timeout:
            result['status'] = 'filtered'
            result['reason'] = 'timeout'
            logger.debug(f"Port {port} is FILTERED (timeout) on {ip_address}")
            
        except socket.error as e:
            result['status'] = 'filtered'
            result['reason'] = str(e)
            logger.debug(f"Port {port} error: {str(e)}")
            
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"Unexpected error scanning port {port}: {str(e)}")
        
        return result
    
    def scan_ports(self, ip_address: str, ports: List[int] = None) -> Dict:
        """
        Scan multiple ports on target IP using threading.
        
        Args:
            ip_address: Target IP address
            ports: List of ports to scan (defaults to CRITICAL_PORTS)
            
        Returns:
            Dictionary containing all scan results
        """
        # Validate IP
        is_valid, normalized_ip = self.validate_ip(ip_address)
        if not is_valid:
            self.results['scan_status'] = 'failed'
            self.results['error'] = normalized_ip
            logger.error(f"Invalid IP: {normalized_ip}")
            return self.results
        
        self.results['target_ip'] = normalized_ip
        
        # Use critical ports if none specified
        if ports is None:
            ports = list(self.CRITICAL_PORTS.keys())
        
        logger.info(f"Starting port scan on {normalized_ip} for {len(ports)} ports")
        start_time = time.time()
        
        try:
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all port scan tasks
                future_to_port = {
                    executor.submit(self.scan_port, normalized_ip, port): port 
                    for port in ports
                }
                
                # Process completed scans
                for future in as_completed(future_to_port):
                    try:
                        result = future.result()
                        
                        # Thread-safe result collection
                        with self.lock:
                            if result['status'] == 'open':
                                self.results['open_ports'].append(result)
                            elif result['status'] == 'closed':
                                self.results['closed_ports'].append(result)
                            elif result['status'] in ['filtered', 'error']:
                                self.results['filtered_ports'].append(result)
                            
                            self.results['ports_scanned'] += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing scan result: {str(e)}")
            
            # Calculate scan duration
            scan_duration = time.time() - start_time
            self.results['scan_duration'] = round(scan_duration, 2)
            self.results['scan_status'] = 'completed'
            
            logger.info(f"Port scan completed in {scan_duration:.2f} seconds")
            logger.info(f"Open ports: {len(self.results['open_ports'])}")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            self.results['scan_status'] = 'failed'
            self.results['error'] = str(e)
        
        return self.results
    
    def get_risk_assessment(self) -> Dict:
        """
        Generate risk assessment based on open ports.
        
        Returns:
            Dictionary containing risk assessment
        """
        assessment = {
            'total_open_ports': len(self.results['open_ports']),
            'critical_ports_open': [],
            'high_severity_ports': [],
            'medium_severity_ports': [],
            'overall_risk_level': 'low',
            'recommendations': []
        }
        
        for port_info in self.results['open_ports']:
            severity = port_info.get('severity', 'low')
            
            if severity == 'critical':
                assessment['critical_ports_open'].append(port_info['port'])
            elif severity == 'high':
                assessment['high_severity_ports'].append(port_info['port'])
            elif severity == 'medium':
                assessment['medium_severity_ports'].append(port_info['port'])
        
        # Determine overall risk level
        if assessment['critical_ports_open']:
            assessment['overall_risk_level'] = 'critical'
            assessment['recommendations'].append(
                'CRITICAL: Close or restrict access to critical ports immediately'
            )
        elif assessment['high_severity_ports']:
            assessment['overall_risk_level'] = 'high'
            assessment['recommendations'].append(
                'HIGH: Review and restrict access to high-severity ports'
            )
        elif assessment['medium_severity_ports']:
            assessment['overall_risk_level'] = 'medium'
            assessment['recommendations'].append(
                'MEDIUM: Monitor and consider restricting medium-severity ports'
            )
        
        # Add specific recommendations
        if 22 in assessment['critical_ports_open']:
            assessment['recommendations'].append(
                'SSH (22) is open: Ensure strong authentication and consider IP whitelisting'
            )
        if 3389 in assessment['critical_ports_open']:
            assessment['recommendations'].append(
                'RDP (3389) is open: Disable if not needed or restrict to VPN'
            )
        if 3306 in assessment['critical_ports_open']:
            assessment['recommendations'].append(
                'MySQL (3306) is open: Move database to private network'
            )
        if 27017 in assessment['critical_ports_open']:
            assessment['recommendations'].append(
                'MongoDB (27017) is open: Implement authentication and network isolation'
            )
        if 6379 in assessment['critical_ports_open']:
            assessment['recommendations'].append(
                'Redis (6379) is open: Require authentication and restrict network access'
            )
        
        return assessment
    
    def export_results(self, format: str = 'json') -> str:
        """
        Export scan results in specified format.
        
        Args:
            format: Export format ('json' or 'text')
            
        Returns:
            Formatted results string
        """
        if format == 'json':
            return json.dumps(self.results, indent=2)
        elif format == 'text':
            return self._format_text_report()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_text_report(self) -> str:
        """
        Format results as human-readable text report.
        
        Returns:
            Formatted text report
        """
        report = []
        report.append("=" * 70)
        report.append("SecureOps Port Scan Report")
        report.append("=" * 70)
        report.append(f"Target IP: {self.results.get('target_ip', 'N/A')}")
        report.append(f"Timestamp: {self.results.get('scan_timestamp', 'N/A')}")
        report.append(f"Status: {self.results.get('scan_status', 'N/A')}")
        report.append(f"Scan Duration: {self.results.get('scan_duration', 'N/A')} seconds")
        report.append(f"Ports Scanned: {self.results.get('ports_scanned', 'N/A')}")
        report.append("")
        
        report.append("SCAN SUMMARY:")
        report.append("-" * 70)
        report.append(f"Open Ports: {len(self.results['open_ports'])}")
        report.append(f"Closed Ports: {len(self.results['closed_ports'])}")
        report.append(f"Filtered Ports: {len(self.results['filtered_ports'])}")
        report.append("")
        
        if self.results['open_ports']:
            report.append("OPEN PORTS DETAILS:")
            report.append("-" * 70)
            for port_info in sorted(self.results['open_ports'], key=lambda x: x['port']):
                report.append(f"Port {port_info['port']}: {port_info['service']}")
                report.append(f"  Service: {port_info['service_description']}")
                report.append(f"  Severity: {port_info['severity'].upper()}")
                report.append("")
        
        # Add risk assessment
        assessment = self.get_risk_assessment()
        report.append("RISK ASSESSMENT:")
        report.append("-" * 70)
        report.append(f"Overall Risk Level: {assessment['overall_risk_level'].upper()}")
        report.append("")
        
        if assessment['recommendations']:
            report.append("RECOMMENDATIONS:")
            for i, rec in enumerate(assessment['recommendations'], 1):
                report.append(f"{i}. {rec}")
        
        report.append("")
        report.append("=" * 70)
        
        return "\n".join(report)


# Example usage
if __name__ == "__main__":
    scanner = PortScanner(timeout=3, max_threads=20)
    
    # Example: Scan target IP
    target_ip = "192.168.1.1"
    results = scanner.scan_ports(target_ip)
    
    # Export results
    print(scanner.export_results(format='text'))
    print("\n\nJSON Export:")
    print(scanner.export_results(format='json'))
    
    # Get risk assessment
    print("\n\nRisk Assessment:")
    print(json.dumps(scanner.get_risk_assessment(), indent=2))
