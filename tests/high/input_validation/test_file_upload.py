import pytest
import requests
import os
from config import *

class TestFileUpload:
    def setup_method(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.base_url = TARGET_URL

    def create_test_file(self, content, extension):
        """Create a test file with specified content and extension"""
        filename = f"test_file.{extension}"
        with open(filename, 'w') as f:
            f.write(content)
        return filename

    def cleanup_test_file(self, filename):
        """Clean up test file"""
        if os.path.exists(filename):
            os.remove(filename)

    def test_file_type_validation(self):
        """Test file type validation"""
        # Test with PHP file
        php_content = "<?php echo 'test'; ?>"
        php_file = self.create_test_file(php_content, 'php')
        
        try:
            with open(php_file, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 400, "PHP files are accepted"
        finally:
            self.cleanup_test_file(php_file)

        # Test with executable file
        exe_content = "MZ"  # DOS header
        exe_file = self.create_test_file(exe_content, 'exe')
        
        try:
            with open(exe_file, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 400, "Executable files are accepted"
        finally:
            self.cleanup_test_file(exe_file)

    def test_file_size_limits(self):
        """Test file size limits"""
        # Create a large file (10MB)
        large_content = "A" * (10 * 1024 * 1024)
        large_file = self.create_test_file(large_content, 'txt')
        
        try:
            with open(large_file, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 413, "Large files are accepted"
        finally:
            self.cleanup_test_file(large_file)

    def test_file_name_validation(self):
        """Test file name validation"""
        # Test with path traversal
        malicious_filename = "../../../etc/passwd"
        content = "test content"
        malicious_file = self.create_test_file(content, 'txt')
        
        try:
            with open(malicious_file, 'rb') as f:
                files = {'file': (malicious_filename, f)}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 400, "Path traversal in filename is accepted"
        finally:
            self.cleanup_test_file(malicious_file)

    def test_file_content_validation(self):
        """Test file content validation"""
        # Test with malicious content
        malicious_content = "<script>alert('xss')</script>"
        malicious_file = self.create_test_file(malicious_content, 'html')
        
        try:
            with open(malicious_file, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 400, "Malicious content is accepted"
        finally:
            self.cleanup_test_file(malicious_file)

    def test_upload_directory_security(self):
        """Test upload directory security"""
        # Test with double extension
        double_ext_file = self.create_test_file("test content", 'jpg.php')
        
        try:
            with open(double_ext_file, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 400, "Double extension files are accepted"
        finally:
            self.cleanup_test_file(double_ext_file)

        # Test with null byte injection
        null_byte_file = self.create_test_file("test content", 'jpg\0.php')
        
        try:
            with open(null_byte_file, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files
                )
                assert response.status_code == 400, "Null byte injection is accepted"
        finally:
            self.cleanup_test_file(null_byte_file) 