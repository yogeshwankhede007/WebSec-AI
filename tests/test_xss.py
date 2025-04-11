import pytest
import requests
from bs4 import BeautifulSoup
from config import *

class TestXSS:
    def setup_method(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.base_url = TARGET_URL

    def check_xss_payload(self, response, payload):
        """Check if XSS payload is reflected in the response"""
        soup = BeautifulSoup(response.text, 'html.parser')
        return payload in str(soup)

    def test_form_input_xss(self):
        """Test XSS in form inputs"""
        test_endpoints = [
            '/contact',
            '/feedback',
            '/comment',
            '/profile/update'
        ]
        
        for endpoint in test_endpoints:
            for payload in XSS_PAYLOADS:
                # Test POST data
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    data={'message': payload}
                )
                assert not self.check_xss_payload(response, payload), f"XSS vulnerability in POST form: {payload}"

                # Test GET parameters
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    params={'q': payload}
                )
                assert not self.check_xss_payload(response, payload), f"XSS vulnerability in GET parameters: {payload}"

    def test_url_parameter_xss(self):
        """Test XSS in URL parameters"""
        for payload in XSS_PAYLOADS:
            response = self.session.get(
                f"{self.base_url}/page/{payload}"
            )
            assert not self.check_xss_payload(response, payload), f"XSS vulnerability in URL path: {payload}"

    def test_cookie_xss(self):
        """Test XSS in cookie values"""
        for payload in XSS_PAYLOADS:
            self.session.cookies.set('test_cookie', payload)
            response = self.session.get(f"{self.base_url}/profile")
            assert not self.check_xss_payload(response, payload), f"XSS vulnerability in cookies: {payload}"

    def test_header_xss(self):
        """Test XSS in HTTP headers"""
        for payload in XSS_PAYLOADS:
            headers = {
                'User-Agent': payload,
                'Referer': payload,
                'X-Forwarded-For': payload
            }
            response = self.session.get(
                f"{self.base_url}/profile",
                headers=headers
            )
            assert not self.check_xss_payload(response, payload), f"XSS vulnerability in headers: {payload}"

    def test_json_xss(self):
        """Test XSS in JSON data"""
        for payload in XSS_PAYLOADS:
            data = {
                'name': payload,
                'description': payload,
                'message': payload
            }
            response = self.session.post(
                f"{self.base_url}/api/data",
                json=data
            )
            assert not self.check_xss_payload(response, payload), f"XSS vulnerability in JSON data: {payload}"

    def test_file_upload_xss(self):
        """Test XSS in file upload content"""
        for payload in XSS_PAYLOADS:
            files = {
                'file': ('test.html', f'<html><body>{payload}</body></html>')
            }
            response = self.session.post(
                f"{self.base_url}/upload",
                files=files
            )
            assert not self.check_xss_payload(response, payload), f"XSS vulnerability in file upload: {payload}"

    def test_stored_xss(self):
        """Test stored XSS vulnerabilities"""
        test_data = {
            'title': 'Test Post',
            'content': XSS_PAYLOADS[0],
            'author': 'Test User'
        }
        
        # Create post with XSS payload
        response = self.session.post(
            f"{self.base_url}/posts/create",
            data=test_data
        )
        assert response.status_code == 200, "Failed to create test post"
        
        # Check if XSS payload is stored and reflected
        response = self.session.get(f"{self.base_url}/posts")
        assert not self.check_xss_payload(response, XSS_PAYLOADS[0]), "Stored XSS vulnerability detected" 