import pytest
import requests
import json
from config import *

class TestAPISecurity:
    def setup_method(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.base_url = TARGET_URL

    def test_api_authentication(self):
        """Test API authentication requirements"""
        for endpoint in API_ENDPOINTS:
            # Test without authentication
            response = self.session.get(f"{self.base_url}{endpoint}")
            assert response.status_code == 401, f"Endpoint {endpoint} doesn't require authentication"

            # Test with invalid token
            headers = {'Authorization': 'Bearer invalid_token'}
            response = self.session.get(f"{self.base_url}{endpoint}", headers=headers)
            assert response.status_code == 401, f"Endpoint {endpoint} accepts invalid token"

    def test_rate_limiting(self):
        """Test API rate limiting"""
        endpoint = API_ENDPOINTS[0]  # Use first endpoint for rate limiting test
        headers = {'Authorization': f'Bearer {TEST_USERNAME}'}
        
        # Make multiple requests quickly
        for _ in range(10):
            response = self.session.get(f"{self.base_url}{endpoint}", headers=headers)
            if response.status_code == 429:
                return  # Rate limiting is working
        pytest.fail("Rate limiting not implemented")

    def test_input_validation(self):
        """Test API input validation"""
        endpoint = API_ENDPOINTS[0]
        headers = {'Authorization': f'Bearer {TEST_USERNAME}'}
        
        # Test with malformed JSON
        response = self.session.post(
            f"{self.base_url}{endpoint}",
            headers=headers,
            data="invalid json"
        )
        assert response.status_code == 400, "API accepts malformed JSON"

        # Test with SQL injection in parameters
        params = {'id': "' OR '1'='1"}
        response = self.session.get(
            f"{self.base_url}{endpoint}",
            headers=headers,
            params=params
        )
        assert response.status_code == 400, "API vulnerable to SQL injection"

    def test_error_handling(self):
        """Test API error handling"""
        endpoint = API_ENDPOINTS[0]
        headers = {'Authorization': f'Bearer {TEST_USERNAME}'}
        
        # Test with non-existent resource
        response = self.session.get(
            f"{self.base_url}{endpoint}/999999",
            headers=headers
        )
        assert response.status_code == 404, "API doesn't handle non-existent resources properly"

        # Test with invalid method
        response = self.session.put(
            f"{self.base_url}{endpoint}",
            headers=headers
        )
        assert response.status_code == 405, "API doesn't handle invalid methods properly"

    def test_sensitive_data_exposure(self):
        """Test for sensitive data exposure in API responses"""
        endpoint = API_ENDPOINTS[0]
        headers = {'Authorization': f'Bearer {TEST_USERNAME}'}
        
        response = self.session.get(f"{self.base_url}{endpoint}", headers=headers)
        data = response.json()
        
        # Check for sensitive data in response
        sensitive_fields = ['password', 'credit_card', 'ssn', 'api_key']
        for field in sensitive_fields:
            assert field not in str(data), f"Sensitive data '{field}' exposed in API response" 