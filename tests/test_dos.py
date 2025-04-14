import requests
import time
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
import socket
import random

class DOSTests:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)

    def test_slowloris(self) -> Dict:
        """Test for Slowloris vulnerability"""
        result = {
            "name": "Slowloris Attack",
            "status": "PASS",
            "details": []
        }
        
        try:
            # Create multiple partial connections
            connections = []
            for _ in range(100):  # Number of connections to test
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.base_url.split('://')[1].split('/')[0], 80))
                sock.send("GET / HTTP/1.1\r\n".encode())
                connections.append(sock)
            
            # Check if server is still responding
            response = self.session.get(self.base_url)
            if response.status_code == 200:
                result["status"] = "FAIL"
                result["details"].append("Server vulnerable to Slowloris attack")
            else:
                result["details"].append("Server protected against Slowloris attack")
            
            # Clean up connections
            for sock in connections:
                sock.close()
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing Slowloris: {str(e)}")
        
        return result

    def test_http_flood(self) -> Dict:
        """Test for HTTP Flood vulnerability"""
        result = {
            "name": "HTTP Flood Attack",
            "status": "PASS",
            "details": []
        }
        
        try:
            start_time = time.time()
            requests_count = 0
            
            # Send rapid HTTP requests
            while time.time() - start_time < 10:  # Test for 10 seconds
                self.session.get(self.base_url)
                requests_count += 1
            
            # Check server response time
            response = self.session.get(self.base_url)
            if response.elapsed.total_seconds() > 2:  # Threshold of 2 seconds
                result["status"] = "FAIL"
                result["details"].append(f"Server vulnerable to HTTP flood (processed {requests_count} requests)")
            else:
                result["details"].append(f"Server handled {requests_count} requests successfully")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing HTTP flood: {str(e)}")
        
        return result

    def test_syn_flood(self) -> Dict:
        """Test for SYN Flood vulnerability"""
        result = {
            "name": "SYN Flood Attack",
            "status": "PASS",
            "details": []
        }
        
        try:
            # Create multiple SYN packets
            for _ in range(100):  # Number of SYN packets to test
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                try:
                    sock.connect((self.base_url.split('://')[1].split('/')[0], 80))
                    sock.close()
                except:
                    pass
            
            # Check if server is still responding
            response = self.session.get(self.base_url)
            if response.status_code != 200:
                result["status"] = "FAIL"
                result["details"].append("Server vulnerable to SYN flood attack")
            else:
                result["details"].append("Server protected against SYN flood attack")
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing SYN flood: {str(e)}")
        
        return result

    def test_connection_limit(self) -> Dict:
        """Test for connection limit vulnerability"""
        result = {
            "name": "Connection Limit",
            "status": "PASS",
            "details": []
        }
        
        try:
            connections = []
            max_connections = 0
            
            # Try to establish multiple connections
            while True:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((self.base_url.split('://')[1].split('/')[0], 80))
                    connections.append(sock)
                    max_connections += 1
                except:
                    break
            
            if max_connections < 100:  # Threshold for minimum connections
                result["status"] = "FAIL"
                result["details"].append(f"Server has low connection limit: {max_connections}")
            else:
                result["details"].append(f"Server has adequate connection limit: {max_connections}")
            
            # Clean up connections
            for sock in connections:
                sock.close()
        except Exception as e:
            result["status"] = "ERROR"
            result["details"].append(f"Error testing connection limit: {str(e)}")
        
        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all DOS/DDOS tests"""
        tests = [
            self.test_slowloris(),
            self.test_http_flood(),
            self.test_syn_flood(),
            self.test_connection_limit()
        ]
        
        return tests 