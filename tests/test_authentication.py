import pytest
import requests
from config import *

class TestAuthentication:
    def setup_method(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.base_url = TARGET_URL

    def test_login_bypass(self):
        """Test for login bypass vulnerabilities"""
        # Test with empty credentials
        response = self.session.post(f"{self.base_url}/login", data={})
        assert response.status_code != 200, "Login bypass vulnerability detected"

        # Test with invalid credentials
        response = self.session.post(f"{self.base_url}/login", 
                                   data={'username': 'invalid', 'password': 'invalid'})
        assert response.status_code != 200, "Login bypass vulnerability detected"

    def test_password_policy(self):
        """Test password policy enforcement"""
        weak_passwords = ['password', '123456', 'qwerty', 'admin']
        for password in weak_passwords:
            response = self.session.post(f"{self.base_url}/register",
                                       data={'username': 'test_user', 'password': password})
            assert response.status_code != 200, f"Weak password '{password}' was accepted"

    def test_session_management(self):
        """Test session management security"""
        # Login and get session cookie
        response = self.session.post(f"{self.base_url}/login",
                                   data={'username': TEST_USERNAME, 'password': TEST_PASSWORD})
        assert response.status_code == 200, "Login failed"
        
        # Test session fixation
        original_cookie = self.session.cookies.get('session_id')
        self.session.get(f"{self.base_url}/logout")
        self.session.get(f"{self.base_url}/login")
        new_cookie = self.session.cookies.get('session_id')
        assert original_cookie != new_cookie, "Session fixation vulnerability detected"

    def test_brute_force_protection(self):
        """Test brute force protection"""
        for i in range(5):  # Try 5 times
            response = self.session.post(f"{self.base_url}/login",
                                       data={'username': TEST_USERNAME, 'password': 'wrong'})
            if i >= 3:  # After 3 failed attempts
                assert response.status_code == 429, "Brute force protection not implemented" 