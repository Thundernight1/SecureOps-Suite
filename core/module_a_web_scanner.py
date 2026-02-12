"""
SecureOps Module A: Web Scanner
Purpose: Scan web applications for security headers and XSS vulnerabilities
Version: 1.0.0
"""

import requests
import re
import json
import logging
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import time

try:
    from cyberark_wrapper import CyberArkIntegrator
except ImportError:
    CyberArkIntegrator = None

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class WebScanner:
    """
    Production-grade web application security scanner.
    Checks for security headers and XSS vulnerabilities.
    """

    # Critical security headers that should be present
    REQUIRED_HEADERS = {
        "X-Frame-Options": "Prevents clickjacking attacks",
        "X-Content-Type-Options": "Prevents MIME type sniffing",
        "Strict-Transport-Security": "Enforces HTTPS",
        "Content-Security-Policy": "Prevents XSS and injection attacks",
        "X-XSS-Protection": "Legacy XSS protection",
        "Referrer-Policy": "Controls referrer information",
    }

    # Common XSS payloads for testing
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "<img src=x onerror=\"alert('XSS')\">",
        "<svg onload=\"alert('XSS')\">",
        'javascript:alert("XSS")',
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "<body onload=\"alert('XSS')\">",
        "<input onfocus=\"alert('XSS')\" autofocus>",
        "<marquee onstart=\"alert('XSS')\"></marquee>",
        "<details open ontoggle=\"alert('XSS')\">",
    ]

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        cyberark_tenant: Optional[str] = None,
        cyberark_user: Optional[str] = None,
        cyberark_pass: Optional[str] = None,
    ):
        """
        Initialize the Web Scanner.

        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            cyberark_tenant: URL of CyberArk tenant (optional)
            cyberark_user: CyberArk username (optional)
            cyberark_pass: CyberArk password (optional)
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecureOps/1.0 Security Scanner"})

        # Initialize CyberArk Integrator
        if CyberArkIntegrator:
            self.ark_integrator = CyberArkIntegrator(
                tenant_url=cyberark_tenant,
                username=cyberark_user,
                password=cyberark_pass,
            )
        else:
            self.ark_integrator = None
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "target_url": None,
            "security_headers": {},
            "missing_headers": [],
            "xss_vulnerabilities": [],
            "scan_status": "pending",
        }

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate and normalize the target URL.

        Args:
            url: Target URL to validate

        Returns:
            Tuple of (is_valid, normalized_url)
        """
        try:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed = urlparse(url)
            if not parsed.netloc:
                return False, "Invalid URL format"

            return True, url
        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            return False, str(e)

    def check_security_headers(self, url: str) -> Dict:
        """
        Check for presence and correctness of security headers.

        Args:
            url: Target URL to scan

        Returns:
            Dictionary containing header analysis results
        """
        header_results = {
            "present_headers": {},
            "missing_headers": [],
            "header_values": {},
        }

        try:
            response = self.session.head(
                url, timeout=self.timeout, allow_redirects=True
            )

            # Check each required header
            for header, description in self.REQUIRED_HEADERS.items():
                if header in response.headers:
                    header_results["present_headers"][header] = {
                        "status": "present",
                        "description": description,
                        "value": response.headers[header],
                    }
                    header_results["header_values"][header] = response.headers[header]
                else:
                    header_results["missing_headers"].append(
                        {
                            "header": header,
                            "description": description,
                            "severity": "medium",
                            "recommendation": f"Add {header} header to HTTP responses",
                        }
                    )

            # Check for additional security headers
            additional_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in additional_headers:
                if header in response.headers:
                    header_results["header_values"][header] = response.headers[header]

            logger.info(f"Security headers check completed for {url}")
            return header_results

        except requests.exceptions.Timeout:
            logger.error(f"Timeout while checking headers for {url}")
            return {"error": "Request timeout", "status": "failed"}
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error for {url}")
            return {"error": "Connection failed", "status": "failed"}
        except Exception as e:
            logger.error(f"Error checking headers: {str(e)}")
            return {"error": str(e), "status": "failed"}

    def scan_for_xss(self, url: str) -> List[Dict]:
        """
        Scan for XSS vulnerabilities by testing common injection points.

        Args:
            url: Target URL to scan

        Returns:
            List of detected XSS vulnerabilities
        """
        vulnerabilities = []

        try:
            # Parse URL to identify potential injection points
            parsed_url = urlparse(url)

            # Test common parameter names
            test_params = [
                "q",
                "search",
                "id",
                "name",
                "email",
                "message",
                "comment",
                "input",
            ]

            for param in test_params:
                for payload in self.XSS_PAYLOADS:
                    try:
                        # Build test URL with payload
                        test_url = f"{url}?{param}={payload}"

                        response = self.session.get(
                            test_url, timeout=self.timeout, allow_redirects=False
                        )

                        # Check if payload is reflected in response
                        if self._is_payload_reflected(payload, response.text):
                            vulnerabilities.append(
                                {
                                    "type": "Reflected XSS",
                                    "parameter": param,
                                    "payload": payload,
                                    "url": test_url,
                                    "severity": "high",
                                    "status_code": response.status_code,
                                    "timestamp": datetime.now().isoformat(),
                                }
                            )
                            logger.warning(
                                f"XSS vulnerability found: {param} parameter in {url}"
                            )

                        # Rate limiting
                        time.sleep(0.1)

                    except requests.exceptions.RequestException as e:
                        logger.debug(f"Request error during XSS test: {str(e)}")
                        continue

            # Test POST method if applicable
            vulnerabilities.extend(self._test_post_xss(url))

            logger.info(
                f"XSS scan completed for {url}. Found {len(vulnerabilities)} vulnerabilities"
            )
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error during XSS scanning: {str(e)}")
            return []

    def _is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """
        Check if XSS payload is reflected in response.

        Args:
            payload: XSS payload to check
            response_text: Response body text

        Returns:
            True if payload is reflected, False otherwise
        """
        # Check for exact payload match
        if payload in response_text:
            return True

        # Check for HTML-encoded versions
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded_payload in response_text:
            return False  # Properly encoded, not vulnerable

        # Check for partial matches that might indicate vulnerability
        script_pattern = r"<script[^>]*>.*?</script>"
        if re.search(script_pattern, response_text, re.IGNORECASE):
            if any(
                keyword in response_text.lower()
                for keyword in ["alert", "onerror", "onload"]
            ):
                return True

        return False

    def _test_post_xss(self, url: str) -> List[Dict]:
        """
        Test for XSS vulnerabilities using POST method.

        Args:
            url: Target URL to scan

        Returns:
            List of detected POST-based XSS vulnerabilities
        """
        vulnerabilities = []

        try:
            # Test common POST parameters
            post_params = [
                "username",
                "password",
                "email",
                "message",
                "content",
                "data",
            ]

            for param in post_params:
                for payload in self.XSS_PAYLOADS[
                    :3
                ]:  # Limit to first 3 payloads for POST
                    try:
                        data = {param: payload}
                        response = self.session.post(
                            url, data=data, timeout=self.timeout, allow_redirects=False
                        )

                        if self._is_payload_reflected(payload, response.text):
                            vulnerabilities.append(
                                {
                                    "type": "Reflected XSS (POST)",
                                    "parameter": param,
                                    "payload": payload,
                                    "method": "POST",
                                    "severity": "high",
                                    "status_code": response.status_code,
                                    "timestamp": datetime.now().isoformat(),
                                }
                            )
                            logger.warning(
                                f"POST XSS vulnerability found: {param} parameter"
                            )

                        time.sleep(0.1)

                    except requests.exceptions.RequestException:
                        continue

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error during POST XSS testing: {str(e)}")
            return []

    def run_full_scan(self, url: str) -> Dict:
        """
        Execute complete web security scan.

        Args:
            url: Target URL to scan

        Returns:
            Complete scan results dictionary
        """
        logger.info(f"Starting full web security scan for {url}")

        # Validate URL
        is_valid, normalized_url = self.validate_url(url)
        if not is_valid:
            self.results["scan_status"] = "failed"
            self.results["error"] = normalized_url
            logger.error(f"Invalid URL: {normalized_url}")
            return self.results

        self.results["target_url"] = normalized_url

        # CyberArk Credential Retrieval
        if self.ark_integrator and self.ark_integrator.is_enabled:
            logger.info("Attempting to retrieve credentials via CyberArk...")
            if self.ark_integrator.authenticate():
                # For this implementation, we assume a standard safe/account naming convention
                # or future config could allow specifying these.
                # Here we try to fetch a default 'scanner_account' for demonstration.
                creds = self.ark_integrator.get_credential(
                    "SecureOps_Safe", "Scanner_Account"
                )
                if creds:
                    logger.info(
                        f"Successfully retrieved credentials for user: {creds.get('username')}"
                    )
                    # In a real scenario, we would use these for a login flow.
                    # For now, we simulate authenticated access by adding a custom header.
                    self.session.headers.update(
                        {
                            "X-SecureOps-Auth-User": creds.get("username"),
                            "X-CyberArk-Managed": "true",
                        }
                    )
                else:
                    logger.warning("Failed to retrieve credentials from Vault.")
            else:
                logger.warning("CyberArk authentication failed.")

        try:
            # Check security headers
            logger.info("Checking security headers...")
            header_results = self.check_security_headers(normalized_url)
            self.results["security_headers"] = header_results

            # Scan for XSS vulnerabilities
            logger.info("Scanning for XSS vulnerabilities...")
            xss_results = self.scan_for_xss(normalized_url)
            self.results["xss_vulnerabilities"] = xss_results

            # Calculate risk score
            risk_score = self._calculate_risk_score(header_results, xss_results)
            self.results["risk_score"] = risk_score
            self.results["scan_status"] = "completed"

            logger.info(f"Scan completed. Risk score: {risk_score}")

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            self.results["scan_status"] = "failed"
            self.results["error"] = str(e)

        return self.results

    def _calculate_risk_score(self, header_results: Dict, xss_results: List) -> float:
        """
        Calculate overall risk score based on findings.

        Args:
            header_results: Security headers analysis
            xss_results: XSS vulnerabilities found

        Returns:
            Risk score from 0.0 to 10.0
        """
        score = 0.0

        # Missing headers contribute to score
        if "missing_headers" in header_results:
            score += len(header_results["missing_headers"]) * 0.5

        # XSS vulnerabilities significantly increase score
        score += len(xss_results) * 3.0

        # Cap at 10.0
        return min(score, 10.0)

    def export_results(self, format: str = "json") -> str:
        """
        Export scan results in specified format.

        Args:
            format: Export format ('json' or 'text')

        Returns:
            Formatted results string
        """
        if format == "json":
            return json.dumps(self.results, indent=2)
        elif format == "text":
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
        report.append("=" * 60)
        report.append("SecureOps Web Security Scan Report")
        report.append("=" * 60)
        report.append(f"Target: {self.results.get('target_url', 'N/A')}")
        report.append(f"Timestamp: {self.results.get('scan_timestamp', 'N/A')}")
        report.append(f"Status: {self.results.get('scan_status', 'N/A')}")
        report.append(f"Risk Score: {self.results.get('risk_score', 'N/A')}/10.0")
        report.append("")

        report.append("SECURITY HEADERS:")
        report.append("-" * 60)
        headers = self.results.get("security_headers", {})
        if "missing_headers" in headers:
            report.append(f"Missing Headers: {len(headers['missing_headers'])}")
            for header in headers["missing_headers"]:
                report.append(f"  - {header['header']}: {header['recommendation']}")
        report.append("")

        report.append("XSS VULNERABILITIES:")
        report.append("-" * 60)
        xss = self.results.get("xss_vulnerabilities", [])
        report.append(f"Total Found: {len(xss)}")
        for vuln in xss:
            report.append(f"  - Type: {vuln.get('type', 'N/A')}")
            report.append(f"    Parameter: {vuln.get('parameter', 'N/A')}")
            report.append(f"    Severity: {vuln.get('severity', 'N/A')}")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)


# Example usage
if __name__ == "__main__":
    scanner = WebScanner(timeout=10)

    # Example: Scan a target URL
    target_url = "https://example.com"
    results = scanner.run_full_scan(target_url)

    # Export results
    print(scanner.export_results(format="text"))
    print("\n\nJSON Export:")
    print(scanner.export_results(format="json"))
