# WebSec-AI (Web Security Testing Framework)

A comprehensive security testing framework for web applications, organized by priority and type to ensure thorough coverage of security aspects.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Tests](https://img.shields.io/badge/security%20tests-passing-brightgreen.svg)](tests/)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

## Framework Structure

### Test Organization

The framework is organized into four priority levels, each containing specific security test types:

#### 1. Critical Priority Tests
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

#### 2. High Priority Tests
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

#### 3. Medium Priority Tests
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

#### 4. Low Priority Tests
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

## Getting Started

### Prerequisites
- Python 3.8+
- Required Python packages (see requirements.txt)
- Security testing tools (see TESTING_APPROACH.md)

### Installation
1. Clone the repository:
   ```bash
   git clone git@github.com:yogeshwankhede007/WebSec-AI.git
   cd WebSec-AI
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
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

## Testing Approach

For detailed information about the testing approach, tools, and procedures, see [TESTING_APPROACH.md](tests/TESTING_APPROACH.md).

## Directory Structure
```
.
├── config/
│   ├── config.py
│   └── test_config.py
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
├── requirements.txt
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

We ❤️ contributions from the community! Whether you're reporting bugs, suggesting features, or submitting code, your help is invaluable.

### How to Contribute

1. **Fork the Repository**
   ```bash
   git clone git@github.com:yogeshwankhede007/WebSec-AI.git
   cd WebSec-AI
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Add Your Tests**
   - Follow the organization structure (priority/type)
   - Include comprehensive test cases
   - Add necessary documentation

4. **Submit a Pull Request**
   - Provide clear description of changes
   - Reference related issues
   - Ensure all tests pass

### Key Ways to Contribute
- 🐛 Report bugs and security issues
- 💡 Suggest new features and improvements
- 📝 Improve documentation
- 🛠️ Submit code changes
- 🔍 Review pull requests
- 📢 Share your experience

### Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms. 
We are committed to providing a welcoming and inclusive environment for all contributors.

### Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations and container parameters.
3. Increase the version numbers in any examples files and the README.md to the new version that this Pull Request would represent.
4. The PR will be merged once you have the sign-off of at least one other developer, or if you do not have permission to do that, you may request the reviewer to merge it for you.

### Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

3. Run tests:
   ```bash
   pytest
   ```

4. Check code style:
   ```bash
   flake8
   ```

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
Made with ❤️ by Yogesh W
</div>
