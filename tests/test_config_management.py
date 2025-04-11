import requests
from typing import List, Dict
import logging
from urllib.parse import urljoin
import re

class ConfigurationManagementTests:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)

    def test_http_methods(self) -> Dict:
        """Test for supported HTTP methods"""
        result = {
            "name": "HTTP Methods",
            "status": "PASS",
            "details": []
        }
        
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"]
        try:
            for method in methods:
                response = self.session.request(method, self.base_url)
                if response.status_code != 405:  # Method Not Allowed
                    result["details"].append(f"Method {method} is allowed")
                    
            # Check for TRACE method specifically
            if "TRACE" in result["details"]:
                result["status"] = "FAIL"
                result["details"].append("TRACE method is enabled, which could be used for XST attacks")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing HTTP methods: {str(e)}")
        
        return result

    def test_security_headers(self) -> Dict:
        """Test for security-related HTTP headers"""
        result = {
            "name": "Security Headers",
            "status": "PASS",
            "details": []
        }
        
        required_headers = {
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-XSS-Protection": "Enables XSS filtering",
            "X-Content-Type-Options": "Prevents MIME type sniffing",
            "Content-Security-Policy": "Controls resources the browser is allowed to load",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser features"
        }
        
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            for header, description in required_headers.items():
                if header not in headers:
                    result["status"] = "FAIL"
                    result["details"].append(f"Missing security header: {header} ({description})")
                else:
                    result["details"].append(f"Security header present: {header}")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error checking security headers: {str(e)}")
        
        return result

    def test_file_extensions(self) -> Dict:
        """Test for file extension handling"""
        result = {
            "name": "File Extension Handling",
            "status": "PASS",
            "details": []
        }
        
        extensions = [
            ".php", ".asp", ".aspx", ".jsp", ".pl", ".py",
            ".txt", ".bak", ".old", ".temp", ".swp"
        ]
        
        try:
            for ext in extensions:
                test_url = urljoin(self.base_url, f"test{ext}")
                response = self.session.get(test_url)
                
                if response.status_code == 200:
                    result["status"] = "FAIL"
                    result["details"].append(f"File extension {ext} is handled by the server")
                else:
                    result["details"].append(f"File extension {ext} is not handled")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing file extensions: {str(e)}")
        
        return result

    def test_directory_listing(self) -> Dict:
        """Test for directory listing exposure"""
        result = {
            "name": "Directory Listing",
            "status": "PASS",
            "details": []
        }
        
        test_dirs = ["/", "/images/", "/css/", "/js/", "/admin/"]
        
        try:
            for directory in test_dirs:
                response = self.session.get(urljoin(self.base_url, directory))
                if "Index of" in response.text or "Directory listing for" in response.text:
                    result["status"] = "FAIL"
                    result["details"].append(f"Directory listing enabled for {directory}")
                else:
                    result["details"].append(f"Directory listing disabled for {directory}")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing directory listing: {str(e)}")
        
        return result

    def test_error_handling(self) -> Dict:
        """Test for error handling and information disclosure"""
        result = {
            "name": "Error Handling",
            "status": "PASS",
            "details": []
        }
        
        test_paths = [
            "nonexistent.php",
            "invalid/page",
            "test' OR '1'='1",
            "../../../../etc/passwd"
        ]
        
        try:
            for path in test_paths:
                response = self.session.get(urljoin(self.base_url, path))
                
                # Check for stack traces or detailed error messages
                if any(indicator in response.text.lower() for indicator in [
                    "stack trace", "error in", "exception", "warning",
                    "notice", "fatal error", "syntax error"
                ]):
                    result["status"] = "FAIL"
                    result["details"].append(f"Detailed error information exposed for {path}")
                else:
                    result["details"].append(f"Error handling appropriate for {path}")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing error handling: {str(e)}")
        
        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all configuration management tests"""
        tests = [
            self.test_http_methods(),
            self.test_security_headers(),
            self.test_file_extensions(),
            self.test_directory_listing(),
            self.test_error_handling()
        ]
        
        return tests 