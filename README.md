Project Overview
A comprehensive Streamlit web application for generating Certificate Signing Requests (CSRs) and private keys using OpenSSL, with automated file management and email notifications.

## 📁 Complete File Structure

```
c:\scripts\cert_automation\
├── 📄 csr_generator.py          # Main Streamlit application (CORE DELIVERABLE)
├── 📄 openssl.cfg               # OpenSSL configuration file (provided)
├── 📄 README.md                 # Comprehensive documentation
├── 📄 requirements.txt          # Python dependencies
├── 📄 start_app.bat            # Windows startup script
├── 📄 test_system.py           # System requirements test
├── 📄 demo.py                  # Demonstration script
├── 📄 secrets_template.toml    # Email configuration template
├── 📄 PROJECT_SUMMARY.md       # This file
├── 📁 .streamlit/
│   ├── 📄 config.toml          # Streamlit configuration
│   └── 📄 secrets.toml         # Email settings (created by user)
├── 📁 temp_certs/              # Temporary files (auto-created)
└── 📁 C:\scripts\certs\        # Output directory for certificates
    ├── 📄 {name}.csr           # Generated CSR files
    └── 📄 {name}.key           # Generated private key files
```
