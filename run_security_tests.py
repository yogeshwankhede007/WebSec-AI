import pytest
import sys
import os
import time
from datetime import datetime
from utils.security_utils import SecurityUtils
from config import *

def run_tests(test_categories=None):
    """Run security tests based on specified categories"""
    start_time = time.time()
    results = {
        'timestamp': datetime.now().isoformat(),
        'target_url': TARGET_URL,
        'test_results': {},
        'security_checks': {}
    }

    # Run network security checks
    print("\nRunning network security checks...")
    hostname = TARGET_URL.split('://')[1].split('/')[0]
    
    # SSL Certificate check
    ssl_valid, ssl_message = SecurityUtils.check_ssl_certificate(hostname)
    results['security_checks']['ssl_certificate'] = {
        'valid': ssl_valid,
        'message': ssl_message
    }

    # Port scanning
    port_results = SecurityUtils.scan_ports(hostname, SCAN_PORTS)
    results['security_checks']['open_ports'] = port_results

    # DNS security check
    dns_results = SecurityUtils.check_dns_security(hostname)
    results['security_checks']['dns_security'] = dns_results

    # Security headers check
    header_results = SecurityUtils.check_security_headers(TARGET_URL)
    results['security_checks']['security_headers'] = header_results

    # SSL/TLS protocols check
    protocol_results = SecurityUtils.check_ssl_protocols(hostname)
    results['security_checks']['ssl_protocols'] = protocol_results

    # Run pytest for specified test categories
    if test_categories is None:
        test_categories = ['authentication', 'api', 'file_upload', 'sql_injection', 'xss', 'csrf']

    for category in test_categories:
        print(f"\nRunning {category} tests...")
        test_file = f"tests/test_{category}.py"
        if os.path.exists(test_file):
            pytest_args = [
                test_file,
                '-v',
                '--tb=short',
                '--capture=no'
            ]
            exit_code = pytest.main(pytest_args)
            results['test_results'][category] = {
                'success': exit_code == 0,
                'exit_code': exit_code
            }
        else:
            print(f"Warning: Test file {test_file} not found")

    # Generate reports
    end_time = time.time()
    results['execution_time'] = end_time - start_time
    
    json_report, html_report = SecurityUtils.generate_report(results)
    print(f"\nReports generated:")
    print(f"JSON report: {json_report}")
    print(f"HTML report: {html_report}")

    return results

if __name__ == "__main__":
    # Parse command line arguments
    test_categories = None
    if len(sys.argv) > 1:
        test_categories = sys.argv[1:]

    # Run tests
    results = run_tests(test_categories)

    # Print summary
    print("\nTest Summary:")
    print(f"Total execution time: {results['execution_time']:.2f} seconds")
    
    print("\nTest Results:")
    for category, result in results['test_results'].items():
        status = "✓" if result['success'] else "✗"
        print(f"{status} {category}: {'Passed' if result['success'] else 'Failed'}")

    print("\nSecurity Check Results:")
    for check, result in results['security_checks'].items():
        if isinstance(result, dict):
            if 'valid' in result:
                status = "✓" if result['valid'] else "✗"
                print(f"{status} {check}: {result['message']}")
            elif 'open_ports' in result:
                print(f"Port Scan Results:")
                for port in result['open_ports']:
                    status = "✓" if port['state'] == 'closed' else "✗"
                    print(f"{status} Port {port['port']}: {port['state']} ({port['service']})") 