import requests
import ssl
import socket
import nmap
import whois
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import json
import os

class SecurityUtils:
    @staticmethod
    def check_ssl_certificate(hostname):
        """Check SSL certificate validity and configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    x509_cert = x509.load_pem_x509_certificate(
                        ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True)),
                        default_backend()
                    )
                    
                    # Check certificate expiration
                    not_after = x509_cert.not_valid_after
                    if not_after < datetime.now():
                        return False, "Certificate has expired"
                    
                    # Check certificate issuer
                    issuer = x509_cert.issuer
                    if not any(org in str(issuer) for org in ['Let\'s Encrypt', 'DigiCert', 'GlobalSign']):
                        return False, "Certificate from untrusted issuer"
                    
                    return True, "Certificate is valid"
        except Exception as e:
            return False, f"SSL certificate error: {str(e)}"

    @staticmethod
    def scan_ports(hostname, ports):
        """Scan specified ports on the host"""
        nm = nmap.PortScanner()
        nm.scan(hostname, ','.join(map(str, ports)))
        
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    results.append({
                        'port': port,
                        'state': state,
                        'service': nm[host][proto][port].get('name', 'unknown')
                    })
        return results

    @staticmethod
    def check_dns_security(domain):
        """Check DNS security configuration"""
        results = {
            'dnssec': False,
            'spf': False,
            'dmarc': False,
            'dkim': False
        }
        
        try:
            # Check DNSSEC
            resolver = dns.resolver.Resolver()
            resolver.set_flags(dns.flags.DO)
            try:
                resolver.resolve(domain, 'A')
                results['dnssec'] = True
            except:
                pass

            # Check SPF
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    if 'v=spf1' in str(record):
                        results['spf'] = True
                        break
            except:
                pass

            # Check DMARC
            try:
                dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    if 'v=DMARC1' in str(record):
                        results['dmarc'] = True
                        break
            except:
                pass

            # Check DKIM
            try:
                dkim_records = resolver.resolve(f'default._domainkey.{domain}', 'TXT')
                results['dkim'] = True
            except:
                pass

        except Exception as e:
            results['error'] = str(e)
        
        return results

    @staticmethod
    def check_security_headers(url):
        """Check security headers in HTTP response"""
        response = requests.get(url, verify=False)
        headers = response.headers
        
        required_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }
        
        results = {}
        for header, message in required_headers.items():
            results[header] = header in headers
            if not results[header]:
                results[f"{header}_message"] = message
        
        return results

    @staticmethod
    def check_ssl_protocols(hostname):
        """Check supported SSL/TLS protocols"""
        protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        results = {}
        
        for protocol in protocols:
            try:
                context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{protocol}'))
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results[protocol] = True
            except:
                results[protocol] = False
        
        return results

    @staticmethod
    def generate_report(data, output_dir='reports'):
        """Generate security report in JSON and HTML formats"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate JSON report
        json_path = os.path.join(output_dir, 'security_report.json')
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        # Generate HTML report
        html_path = os.path.join(output_dir, 'security_report.html')
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .warning {{ color: orange; }}
            </style>
        </head>
        <body>
            <h1>Security Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        """
        
        for section, results in data.items():
            html_content += f"<div class='section'><h2>{section}</h2>"
            if isinstance(results, dict):
                for key, value in results.items():
                    status = 'pass' if value is True else 'fail' if value is False else 'warning'
                    html_content += f"<p class='{status}'>{key}: {value}</p>"
            else:
                html_content += f"<p>{results}</p>"
            html_content += "</div>"
        
        html_content += "</body></html>"
        
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        return json_path, html_path 