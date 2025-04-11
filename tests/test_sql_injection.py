import pytest
import requests
from config import *

class TestSQLInjection:
    def setup_method(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.base_url = TARGET_URL

    def test_login_sql_injection(self):
        """Test SQL injection in login form"""
        for payload in SQL_INJECTION_PAYLOADS:
            # Test username field
            response = self.session.post(
                f"{self.base_url}/login",
                data={'username': payload, 'password': 'test'}
            )
            assert response.status_code != 200, f"SQL injection vulnerability in username field: {payload}"

            # Test password field
            response = self.session.post(
                f"{self.base_url}/login",
                data={'username': 'test', 'password': payload}
            )
            assert response.status_code != 200, f"SQL injection vulnerability in password field: {payload}"

    def test_search_sql_injection(self):
        """Test SQL injection in search functionality"""
        search_endpoints = [
            '/search',
            '/products/search',
            '/accounts/search'
        ]
        
        for endpoint in search_endpoints:
            for payload in SQL_INJECTION_PAYLOADS:
                # Test GET parameter
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    params={'q': payload}
                )
                assert response.status_code != 500, f"SQL injection vulnerability in GET search: {payload}"

                # Test POST parameter
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    data={'search': payload}
                )
                assert response.status_code != 500, f"SQL injection vulnerability in POST search: {payload}"

    def test_filter_sql_injection(self):
        """Test SQL injection in filter parameters"""
        filter_endpoints = [
            '/products/filter',
            '/transactions/filter',
            '/users/filter'
        ]
        
        for endpoint in filter_endpoints:
            for payload in SQL_INJECTION_PAYLOADS:
                # Test numeric filters
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    params={'id': payload}
                )
                assert response.status_code != 500, f"SQL injection vulnerability in numeric filter: {payload}"

                # Test string filters
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    params={'name': payload}
                )
                assert response.status_code != 500, f"SQL injection vulnerability in string filter: {payload}"

    def test_order_by_sql_injection(self):
        """Test SQL injection in ORDER BY clauses"""
        for payload in SQL_INJECTION_PAYLOADS:
            response = self.session.get(
                f"{self.base_url}/products",
                params={'sort': payload}
            )
            assert response.status_code != 500, f"SQL injection vulnerability in ORDER BY: {payload}"

    def test_union_based_sql_injection(self):
        """Test UNION-based SQL injection"""
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--"
        ]
        
        for payload in union_payloads:
            response = self.session.get(
                f"{self.base_url}/products",
                params={'id': payload}
            )
            assert response.status_code != 500, f"UNION-based SQL injection vulnerability: {payload}"

    def test_error_based_sql_injection(self):
        """Test error-based SQL injection"""
        error_payloads = [
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(DATABASE(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
        ]
        
        for payload in error_payloads:
            response = self.session.get(
                f"{self.base_url}/products",
                params={'id': payload}
            )
            assert response.status_code != 500, f"Error-based SQL injection vulnerability: {payload}" 