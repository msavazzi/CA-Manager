# CA Manager

A graphical user interface (GUI) tool built with PyQt5 to manage OpenSSL Certificate Authority (CA) operations. This tool simplifies the process of creating, viewing, and managing SSL/TLS certificates using OpenSSL.

## Features

- 📝 Load and parse OpenSSL configuration files
- 🔑 Create new certificates with customizable attributes
- 📜 View and manage existing certificates
- ⚠️ Monitor certificate expiration status
- 🔄 Renew existing certificates
- ❌ Revoke certificates
- 📋 View detailed certificate information
- 🔍 Filter expired certificates
- 📊 View OpenSSL configuration sections
- 📝 Comprehensive logging of OpenSSL operations
- 🔗 Create complete certificate chains (keychains)

## Requirements

### Software Requirements

- Python 3.x
- PyQt5
- OpenSSL command-line tools
- configparser (Python standard library)

To install the required Python packages:

### OpenSSL CA Configuration Requirements

The tool requires a properly configured OpenSSL CA configuration file (`openssl.cnf`). This file defines the Certificate Authority structure and settings. The configuration should include:

1. Basic CA Structure:
   - Directory structure for certificates, private keys, and CSRs
   - CA certificate and private key locations
   - Serial number and index file locations

2. Required Sections:
   - `[ ca ]` - Basic CA settings
   - `[ CA_default ]` - Default CA settings
   - `[ policy_strict ]` or similar - Certificate signing policies
   - `[ req ]` - Certificate request settings
   - `[ req_distinguished_name ]` - Subject field defaults
   - `[ v3_ca ]` - CA certificate extensions
   - `[ v3_intermediate_ca ]` - Intermediate CA extensions
   - `[ usr_cert ]` - User certificate extensions
   - `[ server_cert ]` - Server certificate extensions

Example directory structure expected by the CA:
```
/path/to/ca
├── certs            # Certificate storage
├── crl              # Certificate revocation lists
├── index.txt        # Database index file
├── index.txt.attr   # Database index attributes
├── newcerts         # New certificates
├── private          # Private key storage
└── serial           # Serial number file
```

For a detailed example of a proper CA configuration file, refer to the [OpenSSL CA Documentation](https://openssl-ca.readthedocs.io/en/latest/intermediate-configuration-file.html).

The configuration file should define:
- Certificate policies and restrictions
- Default values for certificate fields
- Key usage and extended key usage settings
- Path length constraints
- Naming conventions and policies

Key configuration parameters:
```ini
[ CA_default ]
dir               = /path/to/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem
```

⚠️ **Important**: Make sure your CA structure and configuration file are properly set up before using the CA Manager tool. Incorrect configuration can lead to improperly issued certificates or CA operation failures.

```bash
pip install PyQt5
```

Make sure OpenSSL is installed and available in your system's PATH.

## Usage

1. Run the script:
   ```bash
   python CA_Manager.py
   ```

2. Click "Browse..." to select your OpenSSL configuration file (openssl.cnf)
3. Click "Load CA Config & Certs" to load the configuration and existing certificates

## Features in Detail

### Certificate Creation

The "New Certificate" button allows you to create certificates with the following attributes:

- Certificate Name
- CA Authentication (Password for intermediate CA private key)
- Subject Information:
  - Country (C)
  - State/Province (ST)
  - City/Locality (L)
  - Organization (O)
  - Organizational Unit (OU)
  - Common Name (CN)
  - Email Address
- Private Key Settings (optional password protection)

### Certificate Management

- View certificate details including:
  - Subject
  - Issuer
  - Expiry date
  - Status (valid, warning, expired)
  - Configuration sections
- Filter expired certificates using the "Hide Expired Certificates" checkbox
- Renew certificates that are expired or about to expire
- Revoke certificates that are no longer needed or compromised
- Create certificate chains (keychains):
  - Combines selected certificate with intermediate and root CA certificates
  - Available only for valid single certificates (not expired or chains)
  - Creates keychain files in format: `keychain.<certname>.cert.pem`
  - Helps in setting up complete certificate chains for servers

### Logging

- All OpenSSL operations are logged to `ca_manager_openssl.log`
- View logs through Tools > View OpenSSL Log
- Clear logs through Tools > Clear OpenSSL Log

### Configuration

The tool remembers your last used OpenSSL configuration file path in `ca_manager_settings.txt`.

## Certificate Status Icons

- ✅ Valid: Certificate is currently valid
- ⚠️ Warning: Certificate will expire within 30 days
- ❌ Expired: Certificate has expired
- ❓ Invalid: Certificate cannot be read or is invalid
- 📄 Chain: Certificate is part of a certificate chain

## Smart Features

- Automatic loading of default values from OpenSSL configuration
- Matching of certificate names with existing configuration sections
- Support for both encrypted and unencrypted private keys
- Certificate chain detection and handling
- Subject Alternative Name (SAN) support
- Password visibility toggle for secure input
- Smart button activation based on certificate status:
  - Renew/Revoke enabled only for valid certificates
  - Create Keychain available only for valid single certificates
  - Automatic detection of certificate types and chains

## File Structure

The tool works with the following files:

- `CA_Manager.py`: Main application script
- `ca_manager_settings.txt`: Stores last used configuration path
- `ca_manager_openssl.log`: Logs all OpenSSL operations

## Security Features

- Secure password handling with masked input
- Password memory clearing after certificate creation
- Support for encrypted private keys
- Proper handling of CA private key passwords

## Limitations

- Requires proper OpenSSL configuration file
- CA private key password required for signing certificates
- Configuration file must follow OpenSSL configuration format
- Some features may require specific OpenSSL configuration sections

## Error Handling

The tool provides detailed error messages and logs for:
- Invalid CA passwords
- Failed certificate creation
- Configuration parsing errors
- File access issues
- OpenSSL command execution failures

## Tips

1. Always keep your CA private key password secure
2. Regularly check for expiring certificates using the warning status
3. Back up your CA configuration and certificates
4. Review the OpenSSL log for detailed operation history
5. Use meaningful certificate names for easy management

## Contributing

Feel free to submit issues and enhancement requests.

## License

MIT License

Copyright (c) 2025 Massimo Savazzi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Author

Massimo Savazzi  
Email: massimo@savazzi.eu  
GitHub: [msavazzi](https://github.com/msavazzi)