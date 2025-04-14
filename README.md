# Web Security Testing Framework

A comprehensive security testing framework for web applications, organized by priority and type to ensure thorough coverage of security aspects.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Tests](https://img.shields.io/badge/security%20tests-passing-brightgreen.svg)](tests/)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](documentations/CODE_OF_CONDUCT.md)

## Framework Structure

### Test Organization

The framework is organized into four priority levels, each containing specific security test types:

<details>
<summary>1. Critical Priority Tests</summary>

- **Authentication**
  - Session Management
  - Password Policies
  - Multi-Factor Authentication
  - Account Lockout

- **Authorization**
  - Role-Based Access Control
  - Horizontal Privilege Escalation
  - Vertical Privilege Escalation

- **Data Protection**
  - Data Transmission Security
  - Data Storage Security
  - Data Encryption
  - Sensitive Data Handling

- **API Security**
  - API Authentication
  - Rate Limiting
  - Input Validation

- **Business Logic**
  - Workflow Security
  - Business Rule Validation
</details>

<details>
<summary>2. High Priority Tests</summary>

- **Client Security**
  - Content Security Policy
  - XSS Protection
  - Clickjacking Protection

- **Input Validation**
  - SQL Injection
  - Cross-Site Scripting
  - CSRF
  - File Upload Security
  - Command Injection
  - XXE

- **Cryptography**
  - Crypto Implementation
  - Key Management
  - Random Number Generation

- **Access Control**
  - Directory Traversal
  - File Inclusion
  - Path Traversal
</details>

<details>
<summary>3. Medium Priority Tests</summary>

- **Infrastructure Security**
  - SSL/TLS Configuration
  - DNS Security
  - Network Security

- **Error Handling**
  - Error Messages
  - Logging
  - Stack Traces

- **Configuration**
  - Server Configuration
  - Security Headers
  - CORS

- **Session Management**
  - Session Fixation
  - Session Timeout
  - Session Regeneration
</details>

<details>
<summary>4. Low Priority Tests</summary>

- **Information Disclosure**
  - Directory Listing
  - Version Disclosure
  - Technology Stack Disclosure

- **Client Side**
  - Client-Side Storage
  - Local Storage
  - Cookie Security

- **Miscellaneous**
  - HTTP Methods
  - HTTP Headers
  - Robots.txt
</details>

## Getting Started

### Prerequisites
- Python 3.8+
- Required Python packages (see [documentations/requirements.txt](documentations/requirements.txt))
- Security testing tools (see [documentations/TESTING_APPROACH.md](documentations/TESTING_APPROACH.md))

### Installation
1. Clone the repository:
   ```bash
   git clone git@github.com:yogeshwankhede007/WebSec-AI.git
   cd WebSec-AI
   ```

2. Install dependencies:
   ```bash
   pip install -r documentations/requirements.txt
   ```

3. Configure the framework:
   - Update `config.py` with your target application details
   - Set up environment variables if needed

### Usage
1. Run all tests:
   ```bash
   python run_security_tests.py
   ```

2. Run specific test categories:
   ```bash
   python run_security_tests.py --category authentication
   ```

3. Run tests by priority:
   ```bash
   python run_security_tests.py --priority critical
   ```

## Documentation

All documentation files are located in the `documentations` folder:

- [Testing Approach](documentations/TESTING_APPROACH.md)
- [Contributing Guidelines](documentations/CONTRIBUTING.md)
- [Code of Conduct](documentations/CODE_OF_CONDUCT.md)
- [Requirements](documentations/requirements.txt)

## Directory Structure
```
.
├── config/
│   ├── config.py
│   └── test_config.py
├── documentations/
│   ├── CODE_OF_CONDUCT.md
│   ├── CONTRIBUTING.md
│   ├── TESTING_APPROACH.md
│   └── requirements.txt
├── tests/
│   ├── critical/
│   │   ├── authentication/
│   │   ├── authorization/
│   │   ├── data_protection/
│   │   ├── api_security/
│   │   └── business_logic/
│   ├── high/
│   │   ├── client_security/
│   │   ├── input_validation/
│   │   ├── cryptography/
│   │   └── access_control/
│   ├── medium/
│   │   ├── infrastructure_security/
│   │   ├── error_handling/
│   │   ├── configuration/
│   │   └── session_management/
│   └── low/
│       ├── information_disclosure/
│       ├── client_side/
│       └── miscellaneous/
├── utils/
│   ├── security_utils.py
│   └── report_utils.py
├── run_security_tests.py
└── README.md
```

## Features
- Comprehensive security test coverage
- Organized by priority and type
- Automated and manual testing procedures
- Detailed reporting and documentation
- Continuous integration support
- Ethical testing guidelines

## Contributing
For detailed contribution guidelines, please see [documentations/CONTRIBUTING.md](documentations/CONTRIBUTING.md).

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- OWASP Testing Guide
- Security testing community
- Open source security tools
- All contributors who have helped shape this project

## Contact
For questions or suggestions, please:
- Open an issue on GitHub
- Contact the maintainers at yogi.wankhede007@gmail.com

---

<div align="center">
Made with ❤️ by Yogesh W.
</div>
