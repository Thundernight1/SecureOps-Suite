#!/usr/bin/env python3
"""
Physical Security Tool Integration - REAL WORLD
Integrates: Wi-Fi Pineapple, Flipper Zero, SharkTap results into Purple Team reports

NO PLACEHOLDERS - This processes actual tool output
"""

import json
import csv
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import subprocess

# REAL paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "Purple_Team_Operations" / "data" / "scan_results"
DEFAULT_TOOLS_DIR = PROJECT_ROOT / "Purple_Team_Operations" / "tools"


class FlipperZeroParser:
    """Parse REAL Flipper Zero scan results"""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir / "flipper"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def parse_rfid_scan(self, scan_file: Path) -> Dict[str, Any]:
        """
        Parse Flipper Zero RFID/NFC scan results
        Expected format: .sub files from Flipper Zero SD card

        Real-world workflow:
        1. Conduct RFID/NFC scan with Flipper Zero
        2. Connect Flipper to Mac via USB
        3. Copy .sub files from /ext/subghz/ to tools/flipper/
        4. Run this parser
        """

        if not scan_file.exists():
            return {"error": "No scan file found", "recommendations": []}

        content = scan_file.read_text()

        results = {
            "tool": "Flipper Zero",
            "scan_type": "RFID/NFC Access Control",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "risk_level": "UNKNOWN"
        }

        # Parse .sub file format (Flipper Zero SubGHz/RFID format)
        # Example: Protocol: EM4100, Data: 0x1234567890
        protocol_match = re.search(r'Protocol:\s*(\S+)', content)
        data_match = re.search(r'Data:\s*(0x[0-9A-Fa-f]+)', content)

        if protocol_match and data_match:
            results["findings"].append({
                "type": "RFID Card Detected",
                "protocol": protocol_match.group(1),
                "card_data": data_match.group(1),
                "vulnerability": "Card can be cloned",
                "cvss_score": 8.5,
                "business_impact": "Unauthorized physical access possible"
            })
            results["risk_level"] = "CRITICAL"

        # Check for weak/default protocols
        if protocol_match and protocol_match.group(1) in ["EM4100", "HID26"]:
            results["findings"].append({
                "type": "Weak Access Control Protocol",
                "protocol": protocol_match.group(1),
                "vulnerability": "Protocol lacks encryption and anti-cloning",
                "cvss_score": 7.5,
                "recommendation": "Upgrade to HID iCLASS SE or similar encrypted protocol"
            })

        return results

    def parse_nfc_dump(self, dump_file: Path) -> Dict[str, Any]:
        """Parse Flipper Zero NFC dumps"""

        results = {
            "tool": "Flipper Zero",
            "scan_type": "NFC Analysis",
            "timestamp": datetime.now().isoformat(),
            "findings": []
        }

        if not dump_file.exists():
            return results

        content = dump_file.read_text()

        # Parse NFC UID and technology
        uid_match = re.search(r'UID:\s*([0-9A-Fa-f\s]+)', content)
        tech_match = re.search(r'Technology:\s*(\S+)', content)

        if uid_match:
            results["findings"].append({
                "type": "NFC Badge Enumerated",
                "uid": uid_match.group(1).strip(),
                "technology": tech_match.group(1) if tech_match else "Unknown",
                "vulnerability": "Badge UID exposed and clonable",
                "cvss_score": 8.0,
                "business_impact": "Physical security perimeter bypassable"
            })

        return results


class WiFiPineappleParser:
    """Parse REAL Wi-Fi Pineapple Tactical VII results"""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir / "pineapple"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def parse_recon_results(self, recon_json: Path) -> Dict[str, Any]:
        """
        Parse Wi-Fi Pineapple reconnaissance results

        Real-world workflow:
        1. Run Recon module on Wi-Fi Pineapple
        2. Export results as JSON via Pineapple web UI (172.16.42.1:1471)
        3. Save to tools/pineapple/recon_YYYYMMDD.json
        4. Run this parser
        """

        if not recon_json.exists():
            return {"error": "No recon data", "findings": []}

        data = json.loads(recon_json.read_text())

        results = {
            "tool": "Wi-Fi Pineapple Tactical VII",
            "scan_type": "Wireless Network Reconnaissance",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "networks_discovered": 0,
            "clients_discovered": 0
        }

        # Parse Pineapple recon JSON structure
        # Structure varies by firmware version - adapt to your actual output

        if "APs" in data:  # Access Points
            results["networks_discovered"] = len(data["APs"])

            for ap in data["APs"]:
                ssid = ap.get("ssid", "Hidden")
                encryption = ap.get("encryption", "Unknown")
                signal = ap.get("signal", 0)

                # Flag weak encryption
                if encryption in ["WEP", "WPA", "Open"]:
                    results["findings"].append({
                        "type": "Weak Wireless Encryption",
                        "ssid": ssid,
                        "encryption": encryption,
                        "signal_strength": signal,
                        "vulnerability": f"{encryption} is deprecated and crackable",
                        "cvss_score": 8.5 if encryption == "WEP" else 7.0,
                        "business_impact": "Corporate data transmitted over insecure wireless",
                        "recommendation": "Upgrade to WPA3-Enterprise"
                    })

                # Flag hidden SSIDs (security through obscurity)
                if ssid == "Hidden" or ssid == "":
                    results["findings"].append({
                        "type": "Hidden SSID Detected",
                        "bssid": ap.get("bssid", "Unknown"),
                        "vulnerability": "Hidden SSIDs provide false sense of security",
                        "cvss_score": 5.0,
                        "recommendation": "Implement proper authentication, not SSID hiding"
                    })

        if "clients" in data:
            results["clients_discovered"] = len(data["clients"])

            # Flag unencrypted client probes
            for client in data["clients"]:
                if client.get("probes"):
                    results["findings"].append({
                        "type": "Client Device Leaking Network Names",
                        "mac_address": client.get("mac", "Unknown")[:8] + "XX:XX:XX",  # Partial MAC for privacy
                        "probed_networks": client["probes"][:3],  # First 3 networks
                        "vulnerability": "Device broadcasts previously connected SSIDs",
                        "cvss_score": 6.0,
                        "business_impact": "Geolocation tracking and targeted attacks possible",
                        "recommendation": "Disable Wi-Fi when not in use, use VPN"
                    })

        return results

    def parse_evil_portal_results(self, portal_log: Path) -> Dict[str, Any]:
        """Parse Evil Portal (captive portal) test results"""

        results = {
            "tool": "Wi-Fi Pineapple - Evil Portal",
            "scan_type": "Social Engineering Susceptibility Test",
            "timestamp": datetime.now().isoformat(),
            "findings": []
        }

        if not portal_log.exists():
            return results

        # Parse portal access logs
        # Format: timestamp, client_mac, credentials_entered (yes/no)

        content = portal_log.read_text()
        lines = content.strip().split('\n')

        credentials_entered = sum(1 for line in lines if "credentials: yes" in line.lower())
        total_clients = len(lines)

        if total_clients > 0:
            success_rate = (credentials_entered / total_clients) * 100

            results["findings"].append({
                "type": "Social Engineering Vulnerability",
                "test": "Fake captive portal",
                "clients_connected": total_clients,
                "credentials_submitted": credentials_entered,
                "success_rate_percent": round(success_rate, 1),
                "cvss_score": 8.0,
                "business_impact": f"{success_rate:.0f}% of employees fall for credential harvesting",
                "recommendation": "Implement security awareness training on rogue Wi-Fi",
                "comparison": f"Industry average: 5-8%, Your org: {success_rate:.0f}%"
            })

        return results


class SharkTapParser:
    """Parse REAL SharkTap network traffic captures"""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir / "sharktap"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def analyze_pcap(self, pcap_file: Path) -> Dict[str, Any]:
        """
        Analyze SharkTap packet capture with tshark

        Real-world workflow:
        1. Connect SharkTap between target device and network
        2. Capture traffic to PCAP file
        3. Transfer PCAP to Mac
        4. Run this analysis
        """

        if not pcap_file.exists():
            return {"error": "PCAP file not found"}

        results = {
            "tool": "SharkTap + Wireshark/tshark",
            "scan_type": "Network Traffic Analysis",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "pcap_file": str(pcap_file)
        }

        try:
            # Check for unencrypted HTTP traffic
            http_check = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-Y", "http", "-T", "fields", "-e", "http.host"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if http_check.stdout.strip():
                http_hosts = set(http_check.stdout.strip().split('\n'))
                results["findings"].append({
                    "type": "Unencrypted HTTP Traffic",
                    "affected_hosts": list(http_hosts)[:5],  # First 5 hosts
                    "total_hosts": len(http_hosts),
                    "vulnerability": "Data transmitted in cleartext over HTTP",
                    "cvss_score": 7.5,
                    "business_impact": "Sensitive data interceptable via MITM attacks",
                    "recommendation": "Enforce HTTPS-only with HSTS headers"
                })

            # Check for plaintext credentials
            creds_check = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-Y", "http.request.method==POST", "-T", "fields", "-e", "urlencoded-form"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if "password" in creds_check.stdout.lower() or "username" in creds_check.stdout.lower():
                results["findings"].append({
                    "type": "Credentials Transmitted in Cleartext",
                    "protocol": "HTTP POST",
                    "vulnerability": "Authentication credentials sent unencrypted",
                    "cvss_score": 9.0,
                    "business_impact": "Account takeover via passive network sniffing",
                    "recommendation": "Migrate all authentication to HTTPS immediately",
                    "compliance_impact": "Violates PCI-DSS 4.1, SOC 2 CC6.7, WaTech 141.10"
                })

            # Check for DNS queries (potential data exfiltration or C2)
            dns_check = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if dns_check.stdout.strip():
                dns_queries = dns_check.stdout.strip().split('\n')
                suspicious_domains = [d for d in dns_queries if len(d) > 50 or any(c.isdigit() for c in d[:10])]

                if suspicious_domains:
                    results["findings"].append({
                        "type": "Suspicious DNS Activity",
                        "sample_domains": suspicious_domains[:3],
                        "total_suspicious": len(suspicious_domains),
                        "vulnerability": "Potential DNS tunneling or C2 communication",
                        "cvss_score": 7.0,
                        "business_impact": "Data exfiltration or malware command-and-control",
                        "recommendation": "Investigate with EDR/SIEM, block if malicious"
                    })

        except subprocess.TimeoutExpired:
            results["findings"].append({
                "type": "Analysis Error",
                "message": "PCAP file too large for automated analysis",
                "recommendation": "Manually review with Wireshark GUI"
            })
        except FileNotFoundError:
            results["error"] = "tshark not installed. Run: brew install wireshark"

        return results


class PhysicalToolIntegrator:
    """Integrate all physical tool results into unified report"""

    def __init__(self, tools_dir=None, output_dir=None):
        self.tools_dir = Path(tools_dir) if tools_dir else DEFAULT_TOOLS_DIR
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR

        self.flipper = FlipperZeroParser(self.tools_dir)
        self.pineapple = WiFiPineappleParser(self.tools_dir)
        self.sharktap = SharkTapParser(self.tools_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def aggregate_findings(self) -> Dict[str, Any]:
        """Aggregate findings from all physical tools"""

        # Look for latest scan files
        flipper_scans = list((self.tools_dir / "flipper").glob("*.sub"))
        pineapple_scans = list((self.tools_dir / "pineapple").glob("recon_*.json"))
        sharktap_pcaps = list((self.tools_dir / "sharktap").glob("*.pcap"))

        aggregated = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "analyst": "Purple Team Operations",
                "tools_used": ["Flipper Zero", "Wi-Fi Pineapple Tactical VII", "SharkTap"]
            },
            "findings_by_tool": {},
            "all_findings": [],
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

        # Process Flipper Zero results
        if flipper_scans:
            latest_flipper = max(flipper_scans, key=lambda p: p.stat().st_mtime)
            flipper_results = self.flipper.parse_rfid_scan(latest_flipper)
            aggregated["findings_by_tool"]["flipper_zero"] = flipper_results
            aggregated["all_findings"].extend(flipper_results.get("findings", []))

        # Process Wi-Fi Pineapple results
        if pineapple_scans:
            latest_pineapple = max(pineapple_scans, key=lambda p: p.stat().st_mtime)
            pineapple_results = self.pineapple.parse_recon_results(latest_pineapple)
            aggregated["findings_by_tool"]["wifi_pineapple"] = pineapple_results
            aggregated["all_findings"].extend(pineapple_results.get("findings", []))

        # Process SharkTap results
        if sharktap_pcaps:
            latest_pcap = max(sharktap_pcaps, key=lambda p: p.stat().st_mtime)
            sharktap_results = self.sharktap.analyze_pcap(latest_pcap)
            aggregated["findings_by_tool"]["sharktap"] = sharktap_results
            aggregated["all_findings"].extend(sharktap_results.get("findings", []))

        # Calculate risk summary
        for finding in aggregated["all_findings"]:
            cvss = finding.get("cvss_score", 0)
            if cvss >= 9.0:
                aggregated["risk_summary"]["critical"] += 1
            elif cvss >= 7.0:
                aggregated["risk_summary"]["high"] += 1
            elif cvss >= 4.0:
                aggregated["risk_summary"]["medium"] += 1
            else:
                aggregated["risk_summary"]["low"] += 1

        return aggregated

    def export_for_report(self, aggregated: Dict[str, Any]) -> Path:
        """Export findings in format ready for AI proposal generation"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"physical_security_findings_{timestamp}.json"

        # Format for consumption by proposal templates
        report_data = {
            "engagement_type": "Physical Security Assessment",
            "tools_deployed": aggregated["metadata"]["tools_used"],
            "total_findings": len(aggregated["all_findings"]),
            "risk_distribution": aggregated["risk_summary"],
            "critical_findings": [
                f for f in aggregated["all_findings"]
                if f.get("cvss_score", 0) >= 9.0
            ],
            "high_findings": [
                f for f in aggregated["all_findings"]
                if 7.0 <= f.get("cvss_score", 0) < 9.0
            ],
            "medium_findings": [
                f for f in aggregated["all_findings"]
                if 4.0 <= f.get("cvss_score", 0) < 7.0
            ],
            "executive_summary": self._generate_executive_summary(aggregated),
            "remediation_roadmap": self._generate_remediation_roadmap(aggregated)
        }

        output_file.write_text(json.dumps(report_data, indent=2))
        return output_file

    def _generate_executive_summary(self, aggregated: Dict[str, Any]) -> str:
        """Generate executive summary from findings (NOT using fake data)"""

        critical_count = aggregated["risk_summary"]["critical"]
        high_count = aggregated["risk_summary"]["high"]
        total = len(aggregated["all_findings"])

        summary = f"""Physical security assessment identified {total} findings across wireless networks, access control systems, and network traffic analysis.

CRITICAL ISSUES ({critical_count}):
"""
        for finding in aggregated["all_findings"]:
            if finding.get("cvss_score", 0) >= 9.0:
                summary += f"• {finding['type']}: {finding.get('business_impact', 'High risk')}\n"

        summary += f"""
HIGH PRIORITY ({high_count}):
"""
        for finding in aggregated["all_findings"]:
            if 7.0 <= finding.get("cvss_score", 0) < 9.0:
                summary += f"• {finding['type']}\n"

        return summary

    def _generate_remediation_roadmap(self, aggregated: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation roadmap"""

        roadmap = []

        # Sort findings by CVSS score descending
        sorted_findings = sorted(
            aggregated["all_findings"],
            key=lambda f: f.get("cvss_score", 0),
            reverse=True
        )

        for idx, finding in enumerate(sorted_findings, 1):
            roadmap.append({
                "priority": idx,
                "finding": finding["type"],
                "cvss_score": finding.get("cvss_score", 0),
                "remediation": finding.get("recommendation", "Consult security team"),
                "estimated_effort": self._estimate_effort(finding),
                "compliance_impact": finding.get("compliance_impact", "N/A")
            })

        return roadmap

    def _estimate_effort(self, finding: Dict[str, Any]) -> str:
        """Estimate remediation effort based on finding type"""

        finding_type = finding.get("type", "").lower()

        if "encryption" in finding_type or "protocol" in finding_type:
            return "2-4 weeks (infrastructure upgrade required)"
        elif "credential" in finding_type or "password" in finding_type:
            return "1-2 weeks (policy enforcement)"
        elif "training" in finding_type or "awareness" in finding_type:
            return "1-3 months (organizational change)"
        else:
            return "1-2 weeks (configuration change)"


def main():
    parser = argparse.ArgumentParser(description='Physical Tool Integration')
    parser.add_argument('--tools-dir', help=f'Tools directory (default: {DEFAULT_TOOLS_DIR})')
    parser.add_argument('--output-dir', help=f'Output directory (default: {DEFAULT_OUTPUT_DIR})')
    args = parser.parse_args()

    tools_dir = Path(args.tools_dir) if args.tools_dir else DEFAULT_TOOLS_DIR
    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR

    print("=== Physical Tool Integration ===")
    print(f"Tools directory: {tools_dir}")
    print(f"Output directory: {output_dir}")
    print()

    integrator = PhysicalToolIntegrator(tools_dir=tools_dir, output_dir=output_dir)

    # Check for tool data
    flipper_files = list((tools_dir / "flipper").glob("*"))
    pineapple_files = list((tools_dir / "pineapple").glob("*"))
    sharktap_files = list((tools_dir / "sharktap").glob("*"))

    print(f"Flipper Zero files: {len(flipper_files)}")
    print(f"Wi-Fi Pineapple files: {len(pineapple_files)}")
    print(f"SharkTap files: {len(sharktap_files)}")
    print()

    if not any([flipper_files, pineapple_files, sharktap_files]):
        print("No tool data found. Please:")
        print("1. Run your physical security tests")
        print(f"2. Copy results to {tools_dir}")
        print("3. Re-run this script")
        return 1

    # Aggregate findings
    aggregated = integrator.aggregate_findings()

    # Export for reporting
    report_file = integrator.export_for_report(aggregated)

    print("=== Integration Complete ===")
    print(f"Total findings: {len(aggregated['all_findings'])}")
    print(f"Critical: {aggregated['risk_summary']['critical']}")
    print(f"High: {aggregated['risk_summary']['high']}")
    print(f"Medium: {aggregated['risk_summary']['medium']}")
    print(f"Low: {aggregated['risk_summary']['low']}")
    print()
    print(f"Report data: {report_file}")
    print()
    print("This data can now be used in:")
    print("- AI proposal generation")
    print("- Client briefings")
    print("- Technical reports")
    print("- n8n automated workflows")

    return 0


if __name__ == "__main__":
    exit(main())
