import os
import shutil
from pathlib import Path

def cleanup_empty_folders():
    """Remove empty folders from the tests directory"""
    for root, dirs, files in os.walk('tests', topdown=False):
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            if not os.listdir(dir_path):
                os.rmdir(dir_path)
                print(f"Removed empty directory: {dir_path}")

def organize_tests():
    # Define the test organization structure
    test_structure = {
        'critical': {
            'authentication': [
                'test_session_management.py',
                'test_password_policies.py',
                'test_mfa.py',
                'test_account_lockout.py'
            ],
            'authorization': [
                'test_authorization.py',
                'test_horizontal_escalation.py',
                'test_vertical_escalation.py'
            ],
            'data_protection': [
                'test_data_transmission.py',
                'test_data_storage.py',
                'test_data_encryption.py',
                'test_sensitive_data.py'
            ],
            'api_security': [
                'test_api_security.py',
                'test_api_authentication.py',
                'test_api_rate_limiting.py'
            ],
            'business_logic': [
                'test_business_logic.py',
                'test_workflow_security.py'
            ]
        },
        'high': {
            'client_security': [
                'test_client_security.py',
                'test_csp.py',
                'test_xss_protection.py',
                'test_clickjacking.py'
            ],
            'input_validation': [
                'test_sql_injection.py',
                'test_xss.py',
                'test_csrf.py',
                'test_file_upload.py',
                'test_command_injection.py',
                'test_xxe.py'
            ],
            'cryptography': [
                'test_crypto_implementation.py',
                'test_key_management.py',
                'test_random_number.py'
            ],
            'access_control': [
                'test_directory_traversal.py',
                'test_file_inclusion.py',
                'test_path_traversal.py'
            ]
        },
        'medium': {
            'infrastructure_security': [
                'test_infrastructure_security.py',
                'test_ssl_tls.py',
                'test_dns_security.py',
                'test_network_security.py'
            ],
            'error_handling': [
                'test_error_messages.py',
                'test_logging.py',
                'test_stack_traces.py'
            ],
            'configuration': [
                'test_server_config.py',
                'test_security_headers.py',
                'test_cors.py'
            ],
            'session_management': [
                'test_session_fixation.py',
                'test_session_timeout.py',
                'test_session_regeneration.py'
            ]
        },
        'low': {
            'information_disclosure': [
                'test_info_gathering.py',
                'test_directory_listing.py',
                'test_version_disclosure.py'
            ],
            'client_side': [
                'test_client_side_storage.py',
                'test_local_storage.py',
                'test_cookie_security.py'
            ],
            'miscellaneous': [
                'test_http_methods.py',
                'test_http_headers.py',
                'test_robots_txt.py'
            ]
        }
    }

    # Create directory structure
    for priority, types in test_structure.items():
        for test_type, files in types.items():
            dir_path = Path(f'tests/{priority}/{test_type}')
            dir_path.mkdir(parents=True, exist_ok=True)

    # Move files to their respective directories
    for priority, types in test_structure.items():
        for test_type, files in types.items():
            for file in files:
                src = Path(f'tests/{file}')
                dst = Path(f'tests/{priority}/{test_type}/{file}')
                if src.exists():
                    shutil.move(str(src), str(dst))
                    print(f"Moved {file} to {priority}/{test_type}/")
                else:
                    # Create placeholder for missing test files
                    with open(dst, 'w') as f:
                        f.write(f"# Placeholder for {file}\n")
                        f.write("# This file will contain tests for the corresponding security aspect\n")
                    print(f"Created placeholder: {file}")

def create_placeholder_tests():
    # Create placeholder test files for missing test types
    placeholders = {
        'critical/business_logic': [
            'test_business_logic.py',
            'test_workflow_security.py'
        ],
        'high/cryptography': [
            'test_crypto_implementation.py',
            'test_key_management.py',
            'test_random_number.py'
        ],
        'high/access_control': [
            'test_directory_traversal.py',
            'test_file_inclusion.py',
            'test_path_traversal.py'
        ],
        'medium/configuration': [
            'test_server_config.py',
            'test_security_headers.py',
            'test_cors.py'
        ],
        'low/client_side': [
            'test_client_side_storage.py',
            'test_local_storage.py',
            'test_cookie_security.py'
        ],
        'low/miscellaneous': [
            'test_http_methods.py',
            'test_http_headers.py',
            'test_robots_txt.py'
        ]
    }

    for directory, files in placeholders.items():
        dir_path = Path(f'tests/{directory}')
        dir_path.mkdir(parents=True, exist_ok=True)
        
        for file in files:
            file_path = dir_path / file
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    f.write(f"# Placeholder for {file}\n")
                    f.write("# This file will contain tests for the corresponding security aspect\n")
                print(f"Created placeholder: {file}")

if __name__ == "__main__":
    organize_tests()
    create_placeholder_tests()
    cleanup_empty_folders()
    print("Test organization completed!") 