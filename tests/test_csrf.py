import pytest
import requests
from bs4 import BeautifulSoup
from config import *

class TestCSRF:
    def setup_method(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.base_url = TARGET_URL

    def get_csrf_token(self, response):
        """Extract CSRF token from response"""
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrf_token'})
        return csrf_input['value'] if csrf_input else None

    def test_csrf_protection(self):
        """Test CSRF protection on forms"""
        # First get a valid session
        response = self.session.get(f"{self.base_url}/login")
        csrf_token = self.get_csrf_token(response)
        
        if not csrf_token:
            pytest.skip("No CSRF token found in login form")

        # Test protected endpoints
        protected_endpoints = [
            '/transfer',
            '/update_profile',
            '/change_password',
            '/delete_account'
        ]

        for endpoint in protected_endpoints:
            # Test with valid CSRF token
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                data={'csrf_token': csrf_token}
            )
            assert response.status_code != 403, f"CSRF protection not working on {endpoint}"

            # Test without CSRF token
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                data={}
            )
            assert response.status_code == 403, f"CSRF protection missing on {endpoint}"

            # Test with invalid CSRF token
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                data={'csrf_token': 'invalid_token'}
            )
            assert response.status_code == 403, f"CSRF protection not validating token on {endpoint}"

    def test_csrf_cookie_protection(self):
        """Test CSRF cookie protection"""
        # Test if SameSite attribute is set on cookies
        response = self.session.get(f"{self.base_url}/login")
        cookies = self.session.cookies
        
        for cookie in cookies:
            assert 'SameSite' in str(cookie), "CSRF cookie missing SameSite attribute"
            assert 'Secure' in str(cookie), "CSRF cookie missing Secure attribute"

    def test_csrf_header_protection(self):
        """Test CSRF header protection"""
        # Test with missing Origin header
        response = self.session.post(
            f"{self.base_url}/transfer",
            data={'amount': '100'}
        )
        assert response.status_code == 403, "CSRF protection not checking Origin header"

        # Test with invalid Origin header
        headers = {'Origin': 'https://malicious-site.com'}
        response = self.session.post(
            f"{self.base_url}/transfer",
            headers=headers,
            data={'amount': '100'}
        )
        assert response.status_code == 403, "CSRF protection not validating Origin header"

    def test_csrf_token_reuse(self):
        """Test CSRF token reuse protection"""
        # Get initial CSRF token
        response = self.session.get(f"{self.base_url}/login")
        initial_token = self.get_csrf_token(response)
        
        # Use the token once
        response = self.session.post(
            f"{self.base_url}/transfer",
            data={'csrf_token': initial_token}
        )
        
        # Try to reuse the token
        response = self.session.post(
            f"{self.base_url}/transfer",
            data={'csrf_token': initial_token}
        )
        assert response.status_code == 403, "CSRF token reuse allowed"

    def test_csrf_token_expiration(self):
        """Test CSRF token expiration"""
        # Get initial CSRF token
        response = self.session.get(f"{self.base_url}/login")
        initial_token = self.get_csrf_token(response)
        
        # Simulate token expiration by waiting
        import time
        time.sleep(2)  # Wait for 2 seconds
        
        # Try to use expired token
        response = self.session.post(
            f"{self.base_url}/transfer",
            data={'csrf_token': initial_token}
        )
        assert response.status_code == 403, "Expired CSRF token accepted" 