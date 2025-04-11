import requests
from bs4 import BeautifulSoup
import os
import re
from urllib.parse import urljoin
from typing import List, Dict
import logging

class InformationGatheringTests:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)

    def test_robots_txt(self) -> Dict:
        """Test for robots.txt file exposure"""
        result = {
            "name": "Robots.txt Exposure",
            "status": "PASS",
            "details": []
        }
        
        try:
            response = self.session.get(urljoin(self.base_url, "robots.txt"))
            if response.status_code == 200:
                result["status"] = "FAIL"
                result["details"].append("robots.txt is accessible and may expose sensitive paths")
            else:
                result["details"].append("robots.txt is not accessible")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error checking robots.txt: {str(e)}")
        
        return result

    def test_sitemap_xml(self) -> Dict:
        """Test for sitemap.xml file exposure"""
        result = {
            "name": "Sitemap.xml Exposure",
            "status": "PASS",
            "details": []
        }
        
        try:
            response = self.session.get(urljoin(self.base_url, "sitemap.xml"))
            if response.status_code == 200:
                result["status"] = "FAIL"
                result["details"].append("sitemap.xml is accessible and may expose site structure")
            else:
                result["details"].append("sitemap.xml is not accessible")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error checking sitemap.xml: {str(e)}")
        
        return result

    def test_common_files(self) -> Dict:
        """Test for common sensitive file exposure"""
        result = {
            "name": "Common Files Exposure",
            "status": "PASS",
            "details": []
        }
        
        common_files = [
            ".git/config", ".env", "config.php", "wp-config.php",
            "web.config", "phpinfo.php", "server-status", "server-info"
        ]
        
        for file in common_files:
            try:
                response = self.session.get(urljoin(self.base_url, file))
                if response.status_code == 200:
                    result["status"] = "FAIL"
                    result["details"].append(f"Sensitive file {file} is accessible")
            except Exception as e:
                result["details"].append(f"Error checking {file}: {str(e)}")
        
        return result

    def test_technology_fingerprinting(self) -> Dict:
        """Test for technology stack exposure"""
        result = {
            "name": "Technology Fingerprinting",
            "status": "PASS",
            "details": []
        }
        
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            # Check for technology indicators
            tech_indicators = {
                "X-Powered-By": "Server technology",
                "Server": "Server software",
                "X-AspNet-Version": "ASP.NET version",
                "X-AspNetMvc-Version": "ASP.NET MVC version",
                "X-Runtime": "Ruby on Rails version"
            }
            
            for header, description in tech_indicators.items():
                if header in headers:
                    result["status"] = "FAIL"
                    result["details"].append(f"{description} exposed in {header} header")
            
            # Check for framework-specific patterns
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta')
            
            for meta in meta_tags:
                if 'generator' in meta.get('name', '').lower():
                    result["status"] = "FAIL"
                    result["details"].append(f"Framework generator exposed: {meta.get('content')}")
            
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error during technology fingerprinting: {str(e)}")
        
        return result

    def test_user_agent_detection(self) -> Dict:
        """Test for user agent based content differences"""
        result = {
            "name": "User Agent Detection",
            "status": "PASS",
            "details": []
        }
        
        user_agents = {
            "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "bot": "Googlebot/2.1 (+http://www.google.com/bot.html)"
        }
        
        responses = {}
        try:
            for name, ua in user_agents.items():
                headers = {"User-Agent": ua}
                response = self.session.get(self.base_url, headers=headers)
                responses[name] = response.text
            
            # Compare responses
            if len(set(responses.values())) > 1:
                result["status"] = "FAIL"
                result["details"].append("Content varies based on User-Agent")
            else:
                result["details"].append("Content is consistent across User-Agents")
                
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing user agent detection: {str(e)}")
        
        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all information gathering tests"""
        tests = [
            self.test_robots_txt(),
            self.test_sitemap_xml(),
            self.test_common_files(),
            self.test_technology_fingerprinting(),
            self.test_user_agent_detection()
        ]
        
        return tests 