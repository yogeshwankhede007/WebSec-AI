import requests
import logging
from typing import List, Dict
import ssl
import socket
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import hashlib
import json

class CryptographyTests:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)

    def test_ssl_tls_configuration(self) -> Dict:
        """Test SSL/TLS configuration"""
        result = {
            "name": "SSL/TLS Configuration",
            "status": "PASS",
            "details": []
        }
        
        try:
            hostname = self.base_url.split('://')[1].split('/')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if (not_after - datetime.now()).days < 30:
                        result["status"] = "FAIL"
                        result["details"].append("Certificate expires soon")
                    
                    # Check protocol version
                    if ssock.version() in ['SSLv2', 'SSLv3']:
                        result["status"] = "FAIL"
                        result["details"].append("Using insecure SSL version")
                    
                    # Check cipher strength
                    cipher = ssock.cipher()
                    if cipher[1] < 128:  # Key length less than 128 bits
                        result["status"] = "FAIL"
                        result["details"].append("Using weak cipher")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing SSL/TLS: {str(e)}")
        
        return result

    def test_certificate_validation(self) -> Dict:
        """Test certificate validation"""
        result = {
            "name": "Certificate Validation",
            "status": "PASS",
            "details": []
        }
        
        try:
            hostname = self.base_url.split('://')[1].split('/')[0]
            cert = ssl.get_server_certificate((hostname, 443))
            x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            
            # Check certificate chain
            if not x509_cert.issuer == x509_cert.subject:
                result["details"].append("Certificate is not self-signed")
            else:
                result["status"] = "FAIL"
                result["details"].append("Certificate is self-signed")
            
            # Check key usage
            try:
                key_usage = x509_cert.extensions.get_extension_for_class(x509.KeyUsage)
                if not key_usage.value.digital_signature:
                    result["status"] = "FAIL"
                    result["details"].append("Certificate missing digital signature usage")
            except:
                result["status"] = "FAIL"
                result["details"].append("Certificate missing key usage extension")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing certificate: {str(e)}")
        
        return result

    def test_encryption_strength(self) -> Dict:
        """Test encryption strength"""
        result = {
            "name": "Encryption Strength",
            "status": "PASS",
            "details": []
        }
        
        try:
            hostname = self.base_url.split('://')[1].split('/')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check key exchange algorithm
                    if 'RSA' in str(ssock.cipher()[0]):
                        result["details"].append("Using RSA key exchange")
                    else:
                        result["status"] = "FAIL"
                        result["details"].append("Using potentially weak key exchange")
                    
                    # Check hash algorithm
                    cert = ssock.getpeercert(binary_form=True)
                    cert_hash = hashlib.sha256(cert).hexdigest()
                    result["details"].append(f"Certificate hash: {cert_hash}")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing encryption: {str(e)}")
        
        return result

    def test_secure_headers(self) -> Dict:
        """Test for security-related headers"""
        result = {
            "name": "Security Headers",
            "status": "PASS",
            "details": []
        }
        
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Controls resources',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'X-Frame-Options': 'Prevents clickjacking',
                'X-XSS-Protection': 'Enables XSS filtering'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    result["status"] = "FAIL"
                    result["details"].append(f"Missing security header: {header} ({description})")
                else:
                    result["details"].append(f"Security header present: {header}")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing headers: {str(e)}")
        
        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all cryptography tests"""
        tests = [
            self.test_ssl_tls_configuration(),
            self.test_certificate_validation(),
            self.test_encryption_strength(),
            self.test_secure_headers()
        ]
        
        return tests 