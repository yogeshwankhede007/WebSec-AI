import asyncio
import os
from datetime import datetime
from typing import Dict, List
import json
import aiohttp
import requests
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import socket
import whois
import dns.resolver
from config import *

class SecurityTester:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target_url': TARGET_URL,
            'findings': []
        }
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL

    async def check_security_headers(self) -> Dict:
        """Check for security headers in the response"""
        try:
            response = self.session.get(TARGET_URL)
            headers = response.headers
            missing_headers = []
            
            for header in SECURITY_HEADERS:
                if header not in headers:
                    missing_headers.append(header)
            
            return {
                'test': 'Security Headers',
                'status': 'FAIL' if missing_headers else 'PASS',
                'details': {
                    'missing_headers': missing_headers,
                    'present_headers': {h: headers[h] for h in SECURITY_HEADERS if h in headers}
                }
            }
        except Exception as e:
            return {'test': 'Security Headers', 'status': 'ERROR', 'details': str(e)}

    async def check_ssl_tls(self) -> Dict:
        """Check SSL/TLS configuration"""
        try:
            hostname = TARGET_URL.split('://')[1].split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
            return {
                'test': 'SSL/TLS Configuration',
                'status': 'PASS' if version in SSL_VERSIONS else 'FAIL',
                'details': {
                    'ssl_version': version,
                    'certificate': cert
                }
            }
        except Exception as e:
            return {'test': 'SSL/TLS Configuration', 'status': 'ERROR', 'details': str(e)}

    async def check_sql_injection(self) -> Dict:
        """Test for SQL injection vulnerabilities"""
        findings = []
        for payload in SQL_INJECTION_PAYLOADS:
            try:
                # Test login form
                data = {'username': payload, 'password': 'test'}
                response = self.session.post(f"{TARGET_URL}/login", data=data)
                
                # Check for SQL error messages or successful login
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'oracle', 'syntax error']):
                    findings.append(f"Potential SQL injection found with payload: {payload}")
            except Exception as e:
                findings.append(f"Error testing payload {payload}: {str(e)}")
        
        return {
            'test': 'SQL Injection',
            'status': 'FAIL' if findings else 'PASS',
            'details': {'findings': findings}
        }

    async def check_xss(self) -> Dict:
        """Test for XSS vulnerabilities"""
        findings = []
        for payload in XSS_PAYLOADS:
            try:
                # Test various input fields
                data = {'search': payload, 'comment': payload}
                response = self.session.post(TARGET_URL, data=data)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    findings.append(f"Potential XSS found with payload: {payload}")
            except Exception as e:
                findings.append(f"Error testing payload {payload}: {str(e)}")
        
        return {
            'test': 'XSS',
            'status': 'FAIL' if findings else 'PASS',
            'details': {'findings': findings}
        }

    async def check_network_security(self) -> Dict:
        """Check network security configuration"""
        findings = []
        hostname = TARGET_URL.split('://')[1].split('/')[0]
        
        # Port scanning
        for port in SCAN_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    findings.append(f"Port {port} is open")
                sock.close()
            except Exception as e:
                findings.append(f"Error scanning port {port}: {str(e)}")
        
        # DNS configuration
        try:
            dns_records = dns.resolver.resolve(hostname, 'A')
            for rdata in dns_records:
                findings.append(f"DNS A record: {rdata}")
        except Exception as e:
            findings.append(f"DNS resolution error: {str(e)}")
        
        return {
            'test': 'Network Security',
            'status': 'FAIL' if findings else 'PASS',
            'details': {'findings': findings}
        }

    async def run_all_tests(self):
        """Run all security tests"""
        tests = [
            self.check_security_headers(),
            self.check_ssl_tls(),
            self.check_sql_injection(),
            self.check_xss(),
            self.check_network_security()
        ]
        
        results = await asyncio.gather(*tests)
        self.results['findings'].extend(results)
        
        # Generate reports
        self.generate_reports()

    def generate_reports(self):
        """Generate HTML and JSON reports"""
        # Create reports directory if it doesn't exist
        os.makedirs(REPORT_DIR, exist_ok=True)
        
        # Generate JSON report
        with open(os.path.join(REPORT_DIR, JSON_REPORT), 'w') as f:
            json.dump(self.results, f, indent=4)
        
        # Generate HTML report
        html_content = self.generate_html_report()
        with open(os.path.join(REPORT_DIR, HTML_REPORT), 'w') as f:
            f.write(html_content)

    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .test {{ margin: 10px 0; padding: 10px; border: 1px solid #ccc; }}
                .pass {{ background-color: #dff0d8; }}
                .fail {{ background-color: #f2dede; }}
                .error {{ background-color: #fcf8e3; }}
            </style>
        </head>
        <body>
            <h1>Security Test Report</h1>
            <p>Target URL: {TARGET_URL}</p>
            <p>Timestamp: {self.results['timestamp']}</p>
        """
        
        for finding in self.results['findings']:
            html += f"""
            <div class="test {finding['status'].lower()}">
                <h2>{finding['test']}</h2>
                <p>Status: {finding['status']}</p>
                <pre>{json.dumps(finding['details'], indent=2)}</pre>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        return html

async def main():
    tester = SecurityTester()
    await tester.run_all_tests()
    print("Security testing completed. Check the reports directory for results.")

if __name__ == "__main__":
    asyncio.run(main()) 