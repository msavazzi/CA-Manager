###########################################################################
# Certificate Authority Manager Application for OpenSSL
# This module provides utility functions and a dialog class for managing   
# certificates using OpenSSL, including logging, config parsing, and UI.   
###########################################################################

import configparser
import os
import re
import subprocess
import tempfile
import logging
from datetime import datetime, timedelta, timezone
from PyQt5 import QtWidgets, QtGui, QtCore

# Get the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(SCRIPT_DIR, "ca_manager_settings.txt")
LOG_FILE = os.path.join(SCRIPT_DIR, "ca_manager_openssl.log")

# Set up logging for OpenSSL commands
def setup_openssl_logging():
    """Configure logging for OpenSSL commands and results"""
    logger = logging.getLogger('openssl_commands')
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create file handler
    file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    return logger

# Initialize logger
openssl_logger = setup_openssl_logging()

def log_openssl_command(command, result, cwd=None, description=""):
    """Log OpenSSL command execution and results"""
    try:
        # Mask passwords in command for logging
        safe_command = []
        mask_next = False
        for arg in command:
            if mask_next:
                safe_command.append("***MASKED***")
                mask_next = False
            elif arg in ["-passin", "-passout"]:
                safe_command.append(arg)
                mask_next = True
            else:
                safe_command.append(arg)
        
        command_str = " ".join(safe_command)
        
        log_entry = []
        log_entry.append("="*80)
        if description:
            log_entry.append(f"OPERATION: {description}")
        log_entry.append(f"COMMAND: {command_str}")
        if cwd:
            log_entry.append(f"WORKING_DIR: {cwd}")
        log_entry.append(f"RETURN_CODE: {result.returncode}")
        
        if result.stdout:
            log_entry.append("STDOUT:")
            log_entry.append(result.stdout)
        
        if result.stderr:
            log_entry.append("STDERR:")
            log_entry.append(result.stderr)
        
        log_entry.append("="*80)
        log_entry.append("")  # Empty line for separation
        
        openssl_logger.info("\n".join(log_entry))
        
    except Exception as e:
        openssl_logger.error(f"Error logging OpenSSL command: {e}")

def run_openssl_command(command, cwd=None, description="", **kwargs):
    """
    Execute OpenSSL command with logging
    """
    try:
        result = subprocess.run(command, capture_output=True, text=True, cwd=cwd, **kwargs)
        log_openssl_command(command, result, cwd, description)
        return result
    except Exception as e:
        # Create a mock result object for logging
        class MockResult:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr
        
        mock_result = MockResult(-1, "", str(e))
        log_openssl_command(command, mock_result, cwd, f"{description} - EXCEPTION")
        raise

def is_subsection(tag, config):
    """
    Check if a given tag matches a section name in the config.
    The tag is trimmed of spaces and compared case-sensitively.
    """
    trimmed_tag = tag.strip()
    # Config sections in config.sections() come without brackets,
    # so we compare directly to trimmed_tag
    return trimmed_tag in config.sections()

def build_config_tree(config):
    """
    Build a nested tree representation from the config object,
    recognizing subsections (sections in square brackets) as subtrees.
    """
    tree = {}
    for section in config.sections():
        tree[section] = {}
        for key, value in config.items(section):
            if is_subsection(key, config):
                # Add as a subsection to the tree
                if key not in tree[section]:
                    tree[section][key] = {}
            else:
                # Normal key-value pair
                tree[section][key] = value
    return tree

def parse_openssl_config(config_path):
    """
    Parse an OpenSSL config file, returning both
    the configparser object and the constructed tree.
    """
    config = configparser.ConfigParser(strict=False)
    with open(config_path) as f:
        config.read_file(f)
    tree = build_config_tree(config)
    return config, tree

def find_section(config, name):
    name = name.strip().lower()
    for sec in config.sections():
        if sec.strip().lower() == name:
            return sec
    return None

def clean_config_value(value):
    """Clean config value by removing comments and extra whitespace"""
    if isinstance(value, str):
        if '#' in value:
            value = value.split('#')[0]
        return value.strip()
    return value

def detect_cert_type(cert_path):
    """Detect if file contains single certificate or certificate chain"""
    try:
        with open(cert_path, 'r') as f:
            content = f.read()
            cert_count = content.count('-----BEGIN CERTIFICATE-----')
            return "chain" if cert_count > 1 else "single"
    except Exception:
        return "single"

def extract_certificates(cert_path):
    """Extract individual certificates from a chain file"""
    try:
        with open(cert_path, 'r') as f:
            content = f.read()
            certificates = []
            cert_blocks = content.split('-----BEGIN CERTIFICATE-----')
            for i, block in enumerate(cert_blocks[1:], 1):  # Skip first empty split
                if '-----END CERTIFICATE-----' in block:
                    cert_content = '-----BEGIN CERTIFICATE-----' + block.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----'
                    certificates.append(cert_content)
            return certificates
    except Exception:
        return []

def resolve_path(path, variables):
    def replacer(match):
        var_name = match.group(1) or match.group(2)
        return variables.get(var_name, match.group(0))

    pattern = re.compile(r'\$(\w+)|\$\{(\w+)\}')
    resolved = pattern.sub(replacer, path)
    return os.path.normpath(resolved)

def get_certificate_info(cert_path):
    try:
        result = run_openssl_command(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate"],
            description=f"Get certificate info for {os.path.basename(cert_path)}"
        )
        output = result.stdout
        
        subject = issuer = None
        enddate_str = None
        
        for line in output.splitlines():
            if line.startswith("subject="):
                subject = line[len("subject="):].strip()
            elif line.startswith("issuer="):
                issuer = line[len("issuer="):].strip()
            elif line.startswith("notAfter="):
                enddate_str = line[len("notAfter="):].strip()
        
        expiry = None
        if enddate_str:
            expiry = datetime.strptime(enddate_str, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)  # Make timezone-aware        

        return {"subject": subject, "issuer": issuer, "expiry": expiry}
    except Exception as e:
        return {"error": str(e)}

def certificate_status_icon(expiry, cert_type="single", has_error=False):
    if has_error or expiry is None:
        return "invalid"
    
    now = datetime.now(timezone.utc)
    
    if cert_type == "chain":
        # For chains, still check expiry but use chain icon if valid
        if expiry < now:
            return "expired"
        elif expiry < now + timedelta(days=30):
            return "warning"
        else:
            return "chain"
    elif expiry < now:
        return "expired"
    elif expiry < now + timedelta(days=30):
        return "warning"
    else:
        return "valid"

def get_certificate_san(cert_path):
    try:
        result = run_openssl_command(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
            description=f"Get SAN entries for {os.path.basename(cert_path)}"
        )
        output = result.stdout
        
        san_lines = []
        in_san = False
        
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("X509v3 Subject Alternative Name:"):
                in_san = True
                continue
            
            if in_san:
                if line == "":
                    break
                san_lines.append(line)
        
        san_str = " ".join(san_lines)
        san_entries = []
        parts = san_str.split(',')
        
        for p in parts:
            p = p.strip()
            if p.startswith("DNS:"):
                san_entries.append(p[4:])
            elif p.startswith("IP Address:"):
                san_entries.append(p[11:])
        
        return san_entries
    except Exception:
        return []

def save_last_config_path(config_path):
    try:
        with open(SETTINGS_FILE, "w") as f:
            f.write(config_path)
    except Exception:
        pass
def save_root_ca_path(root_ca_path):
    """Save the last used root CA certificate path to settings"""
    try:
        settings_dict = {}
        
        # Load existing settings if they exist
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    settings_dict['last_config_path'] = content
        
        # Add root CA path
        settings_dict['root_ca_path'] = root_ca_path
        
        # Save settings as key-value pairs
        with open(SETTINGS_FILE, 'w') as f:
            for key, value in settings_dict.items():
                f.write(f"{key}={value}\n")
                
    except Exception:
        pass  # Fail silently like other settings functions

def load_root_ca_path():
    """Load the last used root CA certificate path from settings"""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('root_ca_path='):
                        return line[len('root_ca_path='):]
        except Exception:
            pass
    return ""

def load_last_config_path():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def get_all_linked_sections(config, start_section, visited=None):
    if visited is None:
        visited = set()
    
    sec = find_section(config, start_section)
    if not sec or sec in visited:
        return []
    
    visited.add(sec)
    sections = [sec]
    
    for k, v in config[sec].items():
        clean_v = clean_config_value(v)
        
        # Check if the value is a subsection reference using the new function
        if is_subsection(clean_v, config):
            sections += get_all_linked_sections(config, clean_v, visited)
        elif clean_v.startswith("@"):
            linked_sec = clean_v[1:]
            sections += get_all_linked_sections(config, linked_sec, visited)
        elif k.lower() in ['default_ca', 'policy', 'x509_extensions', 'req_extensions', 'crl_extensions']:
            linked_sec_name = find_section(config, clean_v)
            if linked_sec_name:
                sections += get_all_linked_sections(config, linked_sec_name, visited)
    
    return sections

def format_sections(config, sections):
    out = ""
    for sec in sections:
        if sec in config:
            out += f"[{sec}]\n"
            for k, v in config[sec].items():
                out += f" {k} = {v}\n"
            out += "\n"
    return out

class CertificateItem:
    """Helper class to store certificate data"""
    def __init__(self, cert_path, cert_type, status, subject, issuer, expiry_str, icon):
        self.cert_path = cert_path
        self.cert_type = cert_type
        self.status = status
        self.subject = subject
        self.issuer = issuer
        self.expiry_str = expiry_str
        self.icon = icon
        self.cert_file = os.path.basename(cert_path)

class NewCertificateDialog(QtWidgets.QDialog):
    def __init__(self, parent, config, config_path, ca_sections):
        super().__init__(parent)
        self.config = config
        self.config_path = config_path
        self.ca_sections = ca_sections
        self.setupUI()
        self.load_defaults()

    def setupUI(self):
        self.setWindowTitle("Create New Certificate")
        self.setModal(True)
        self.resize(500, 700)  # Increased height to accommodate new field

        layout = QtWidgets.QVBoxLayout()

        # Certificate name
        cert_name_layout = QtWidgets.QHBoxLayout()
        cert_name_layout.addWidget(QtWidgets.QLabel("Certificate Name:"))
        self.cert_name_edit = QtWidgets.QLineEdit()
        self.cert_name_edit.setPlaceholderText("e.g., homeassistant, nas-server")
        self.cert_name_edit.textChanged.connect(self.check_cn_match)
        cert_name_layout.addWidget(self.cert_name_edit)
        layout.addLayout(cert_name_layout)

        # Match status label
        self.match_label = QtWidgets.QLabel("")
        self.match_label.setStyleSheet("color: blue; font-weight: bold;")
        layout.addWidget(self.match_label)

        # CA Password Section
        ca_group = QtWidgets.QGroupBox("CA Authentication")
        ca_layout = QtWidgets.QFormLayout()

        self.ca_password_edit = QtWidgets.QLineEdit()
        self.ca_password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ca_password_edit.setPlaceholderText("Password for intermediate CA private key")
        ca_layout.addRow("CA Private Key Password:", self.ca_password_edit)

        # Add show/hide password checkbox
        self.show_ca_password_cb = QtWidgets.QCheckBox("Show password")
        self.show_ca_password_cb.stateChanged.connect(self.toggle_ca_password_visibility)
        ca_layout.addRow("", self.show_ca_password_cb)

        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)

        # Subject information
        subject_group = QtWidgets.QGroupBox("Certificate Subject Information")
        subject_layout = QtWidgets.QFormLayout()

        self.country_edit = QtWidgets.QLineEdit()
        self.country_edit.setPlaceholderText("e.g., US")
        subject_layout.addRow("Country (C):", self.country_edit)

        self.state_edit = QtWidgets.QLineEdit()
        self.state_edit.setPlaceholderText("e.g., California")
        subject_layout.addRow("State/Province (ST):", self.state_edit)

        self.city_edit = QtWidgets.QLineEdit()
        self.city_edit.setPlaceholderText("e.g., San Francisco")
        subject_layout.addRow("City/Locality (L):", self.city_edit)

        self.org_edit = QtWidgets.QLineEdit()
        self.org_edit.setPlaceholderText("e.g., My Company")
        subject_layout.addRow("Organization (O):", self.org_edit)

        self.ou_edit = QtWidgets.QLineEdit()
        self.ou_edit.setPlaceholderText("e.g., IT Department")
        subject_layout.addRow("Organizational Unit (OU):", self.ou_edit)

        self.cn_edit = QtWidgets.QLineEdit()
        self.cn_edit.setPlaceholderText("e.g., server.domain.com")
        self.cn_edit.textChanged.connect(self.check_cn_match)
        subject_layout.addRow("Common Name (CN):", self.cn_edit)

        self.email_edit = QtWidgets.QLineEdit()
        self.email_edit.setPlaceholderText("e.g., admin@domain.com")
        subject_layout.addRow("Email Address:", self.email_edit)

        subject_group.setLayout(subject_layout)
        layout.addWidget(subject_group)

        # Key password
        key_group = QtWidgets.QGroupBox("Private Key Settings")
        key_layout = QtWidgets.QFormLayout()

        self.key_password_edit = QtWidgets.QLineEdit()
        self.key_password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.key_password_edit.setPlaceholderText("Password for private key (optional)")
        key_layout.addRow("Key Password:", self.key_password_edit)

        # Add show/hide password checkbox for key password
        self.show_key_password_cb = QtWidgets.QCheckBox("Show password")
        self.show_key_password_cb.stateChanged.connect(self.toggle_key_password_visibility)
        key_layout.addRow("", self.show_key_password_cb)

        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.create_button = QtWidgets.QPushButton("Create Certificate")
        self.create_button.clicked.connect(self.create_certificate)
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addStretch()
        button_layout.addWidget(self.create_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def toggle_ca_password_visibility(self):
        """Toggle visibility of CA password field"""
        if self.show_ca_password_cb.isChecked():
            self.ca_password_edit.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.ca_password_edit.setEchoMode(QtWidgets.QLineEdit.Password)

    def toggle_key_password_visibility(self):
        """Toggle visibility of key password field"""
        if self.show_key_password_cb.isChecked():
            self.key_password_edit.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.key_password_edit.setEchoMode(QtWidgets.QLineEdit.Password)

    def load_defaults(self):
        try:
            req_section = find_section(self.config, 'req')
            if not req_section:
                return

            dn_section_name = clean_config_value(self.config[req_section].get('distinguished_name', ''))
            if not dn_section_name:
                return

            dn_section = find_section(self.config, dn_section_name)
            if not dn_section or dn_section not in self.config:
                return

            section_data = self.config[dn_section]

            # Read defaults directly by key, including numeric prefixes
            self.country_edit.setText(section_data.get('countryName_default', ''))
            self.state_edit.setText(section_data.get('stateOrProvinceName_default', ''))
            self.city_edit.setText(section_data.get('localityName_default', ''))

            # For Organization, check numeric prefix keys
            org_value = ''
            for key in section_data:
                if key.lower().endswith('organizationname_default'):
                    org_value = section_data[key]
                    break
            self.org_edit.setText(org_value)

            self.ou_edit.setText(section_data.get('organizationalUnitName_default', ''))
            self.email_edit.setText(section_data.get('emailAddress_default', ''))

        except Exception as e:
            print(f"Error loading defaults: {e}")

    def check_cn_match(self):
        cert_name = self.cert_name_edit.text().strip().lower()

        matched_section = None
        matching_type = ""
        dns1_value = ""

        # 1. Check exact section name match first (case insensitive)
        for section_name in self.config.sections():
            if section_name.strip().lower() == cert_name:
                matched_section = section_name
                matching_type = "section"
                # Try to find DNS.1 value in referenced altnames section
                dns1_value = self.get_dns1_from_section(section_name)
                break

        # 2. If no match, check DNS entries in all sections for a match
        if not matched_section:
            for section_name in self.config.sections():
                for key, val in self.config[section_name].items():
                    if key.strip().lower().startswith("dns"):
                        clean_val = clean_config_value(val).strip().lower()
                        if clean_val == cert_name:
                            matched_section = section_name
                            matching_type = "dns"
                            dns1_value = clean_config_value(val).strip()  # Use the matched DNS value
                            break
                if matched_section:
                    break

        if matched_section:
            self.match_label.setText(f"✓ Match found: [{matched_section}] ({'section name' if matching_type=='section' else 'DNS entry'})")
            self.match_label.setStyleSheet("color: green; font-weight: bold;")
            self.matched_section = matched_section
            
            # Always update CN field when a match is found (replace existing value)
            if dns1_value:
                self.cn_edit.setText(dns1_value)
                
            # Also update other fields from the matched section if available
            self.update_fields_from_matched_section(matched_section)
        else:
            self.match_label.setText("ℹ No matching configuration section or DNS entry found")
            self.match_label.setStyleSheet("color: orange; font-weight: bold;")
            self.matched_section = None

    def update_fields_from_matched_section(self, section_name):
        """
        Update dialog fields with values from the matched configuration section
        """
        try:
            if section_name not in self.config:
                return
                
            section_data = self.config[section_name]
            
            # Look for subject-related fields in the matched section
            # These might be direct values or references to other sections
            
            # Check if there are any subject field overrides in this section
            subject_fields = {
                'countryname': 'country_edit',
                'stateorprovincename': 'state_edit', 
                'localityname': 'city_edit',
                'organizationname': 'org_edit',
                'organizationalunitname': 'ou_edit',
                'emailaddress': 'email_edit'
            }
            
            for key, value in section_data.items():
                key_lower = key.strip().lower()
                clean_val = clean_config_value(value).strip()
                
                # Check for direct subject field matches
                for config_field, widget_name in subject_fields.items():
                    if key_lower == config_field or key_lower.endswith(f'{config_field}_default'):
                        widget = getattr(self, widget_name, None)
                        if widget and clean_val:
                            widget.setText(clean_val)
                            
        except Exception as e:
            print(f"Error updating fields from section {section_name}: {e}")

    def get_dns1_from_section(self, section_name):
        """
        Get DNS.1 value from a certificate section by following subjectAltName references
        """
        try:
            if section_name not in self.config:
                return ""
            
            section_data = self.config[section_name]
            
            # Look for subjectAltName reference
            for key, value in section_data.items():
                if key.strip().lower() == 'subjectaltname':
                    clean_val = clean_config_value(value).strip()
                    
                    # Check if it references another section (format: @altnames_something)
                    if clean_val.startswith('@'):
                        altnames_section = clean_val[1:]  # Remove @ prefix
                        
                        # Find the altnames section (case insensitive)
                        altnames_section_real = find_section(self.config, altnames_section)
                        if altnames_section_real and altnames_section_real in self.config:
                            altnames_data = self.config[altnames_section_real]
                            
                            # Look for DNS.1 entry
                            dns1_key = None
                            for alt_key in altnames_data.keys():
                                if alt_key.strip().lower() == 'dns.1':
                                    dns1_key = alt_key
                                    break
                            
                            if dns1_key:
                                return clean_config_value(altnames_data[dns1_key]).strip()
                    break
            
            # If no subjectAltName found, look directly for DNS.1 in current section
            for key, value in section_data.items():
                if key.strip().lower() == 'dns.1':
                    return clean_config_value(value).strip()
                    
        except Exception as e:
            print(f"Error getting DNS.1 from section {section_name}: {e}")
        
        return ""

    def create_certificate(self):
        """Execute the certificate creation workflow with logging"""
        cert_name = self.cert_name_edit.text().strip()
        if not cert_name:
            QtWidgets.QMessageBox.warning(self, "Missing Information", "Please enter a certificate name.")
            return

        cn = self.cn_edit.text().strip()
        if not cn:
            QtWidgets.QMessageBox.warning(self, "Missing Information", "Please enter a Common Name (CN).")
            return

        # Get CA private key password from the dialog field
        ca_password = self.ca_password_edit.text().strip()
        if not ca_password:
            QtWidgets.QMessageBox.warning(self, "Missing Information", "Please enter the CA private key password.")
            return

        try:
            # Log the start of certificate creation
            openssl_logger.info(f"Starting certificate creation for: {cert_name}")
            openssl_logger.info(f"Common Name: {cn}")
            
            # Get paths from config
            config_dir = os.path.dirname(os.path.abspath(self.config_path))
            ca_section = find_section(self.config, 'ca')
            default_ca_name = clean_config_value(self.config[ca_section].get('default_ca', ''))
            default_ca_section = find_section(self.config, default_ca_name)

            # Get base directory first
            dir_raw = clean_config_value(self.config[default_ca_section].get('dir', '.'))
            if not os.path.isabs(dir_raw):
                base_dir = os.path.normpath(os.path.join(config_dir, dir_raw))
            else:
                base_dir = os.path.normpath(dir_raw)

            # Create variables dictionary for path resolution
            variables = {
                'dir': base_dir,
                'config_dir': config_dir
            }

            # Resolve directory paths using variable substitution
            private_dir_raw = clean_config_value(self.config[default_ca_section].get('private_dir', 'private'))
            private_dir = resolve_path(private_dir_raw, variables)
            if not os.path.isabs(private_dir):
                private_dir = os.path.join(base_dir, private_dir)

            # For CSR directory, use a consistent approach
            csr_dir = os.path.join(base_dir, 'csr')  # Always relative to base_dir

            # Resolve certs directory properly
            certs_dir_raw = clean_config_value(self.config[default_ca_section].get('certs', 'certs'))
            certs_dir = resolve_path(certs_dir_raw, variables)
            if not os.path.isabs(certs_dir):
                certs_dir = os.path.join(base_dir, certs_dir)

            # Log directory paths for debugging
            openssl_logger.info(f"Config directory: {config_dir}")
            openssl_logger.info(f"Base directory (dir): {base_dir}")
            openssl_logger.info(f"Private directory raw: {private_dir_raw}")
            openssl_logger.info(f"Private directory resolved: {private_dir}")
            openssl_logger.info(f"CSR directory: {csr_dir}")
            openssl_logger.info(f"Certs directory raw: {certs_dir_raw}")
            openssl_logger.info(f"Certs directory resolved: {certs_dir}")

            # Ensure directories exist
            os.makedirs(private_dir, exist_ok=True)
            os.makedirs(csr_dir, exist_ok=True)
            os.makedirs(certs_dir, exist_ok=True)

            # File paths
            key_file = os.path.join(private_dir, f"{cert_name}.key.pem")
            decrypted_key_file = os.path.join(private_dir, f"{cert_name}.decrypted.key.pem")
            csr_file = os.path.join(csr_dir, f"{cert_name}.csr.pem")
            cert_file = os.path.join(certs_dir, f"{cert_name}.cert.pem")

            # Log file paths
            openssl_logger.info(f"Key file: {key_file}")
            openssl_logger.info(f"Decrypted key file: {decrypted_key_file}")
            openssl_logger.info(f"CSR file: {csr_file}")
            openssl_logger.info(f"Certificate file: {cert_file}")

            # Build subject string
            subject_parts = []
            if self.country_edit.text().strip():
                subject_parts.append(f"C={self.country_edit.text().strip()}")
            if self.state_edit.text().strip():
                subject_parts.append(f"ST={self.state_edit.text().strip()}")
            if self.city_edit.text().strip():
                subject_parts.append(f"L={self.city_edit.text().strip()}")
            if self.org_edit.text().strip():
                subject_parts.append(f"O={self.org_edit.text().strip()}")
            if self.ou_edit.text().strip():
                subject_parts.append(f"OU={self.ou_edit.text().strip()}")
            subject_parts.append(f"CN={cn}")
            if self.email_edit.text().strip():
                subject_parts.append(f"emailAddress={self.email_edit.text().strip()}")

            subject = "/" + "/".join(subject_parts)
            openssl_logger.info(f"Certificate subject: {subject}")

            # Step 1: Generate private key
            self.update_status("Generating private key...")
            key_password = self.key_password_edit.text().strip()
            if key_password:
                # Generate encrypted key
                result = run_openssl_command([
                    "openssl", "genrsa", "-aes256", "-passout", f"pass:{key_password}",
                    "-out", key_file, "2048"
                ], cwd=base_dir, description=f"Generate encrypted private key for {cert_name}")
            else:
                # Generate unencrypted key
                result = run_openssl_command([
                    "openssl", "genrsa", "-out", key_file, "2048"
                ], cwd=base_dir, description=f"Generate unencrypted private key for {cert_name}")

            if result.returncode != 0:
                raise Exception(f"Failed to generate private key: {result.stderr}")

            # Step 2: Create decrypted version if key was encrypted
            if key_password:
                self.update_status("Creating decrypted key...")
                result = run_openssl_command([
                    "openssl", "rsa", "-in", key_file, "-passin", f"pass:{key_password}",
                    "-out", decrypted_key_file
                ], cwd=base_dir, description=f"Create decrypted key for {cert_name}")
                if result.returncode != 0:
                    raise Exception(f"Failed to create decrypted key: {result.stderr}")
            else:
                # Copy unencrypted key as decrypted version
                import shutil
                shutil.copy2(key_file, decrypted_key_file)
                openssl_logger.info(f"Copied unencrypted key to decrypted key file: {decrypted_key_file}")

            # Step 3: Generate CSR
            self.update_status("Generating certificate request...")
            csr_cmd = [
                "openssl", "req", "-config", self.config_path,
                "-key", decrypted_key_file, "-new", "-sha256",
                "-out", csr_file, "-subj", subject
            ]

            result = run_openssl_command(csr_cmd, cwd=base_dir, description=f"Generate CSR for {cert_name}")
            if result.returncode != 0:
                raise Exception(f"Failed to generate CSR: {result.stderr}")

            # Step 4: Sign certificate using CA password from dialog
            self.update_status("Signing certificate...")
            sign_cmd = [
                "openssl", "ca", "-config", self.config_path, "-days", "375",
                "-notext", "-md", "sha256", "-in", csr_file, "-out", cert_file,
                "-passin", f"pass:{ca_password}", "-batch"
            ]

            # Add extensions if matched section found
            if hasattr(self, 'matched_section') and self.matched_section:
                sign_cmd.extend(["-extensions", self.matched_section])
                openssl_logger.info(f"Using extensions section: {self.matched_section}")

            result = run_openssl_command(sign_cmd, cwd=base_dir, description=f"Sign certificate for {cert_name}")
            if result.returncode != 0:
                # Check for common password-related errors
                if "bad decrypt" in result.stderr.lower() or "wrong password" in result.stderr.lower():
                    QtWidgets.QMessageBox.critical(
                        self, "Incorrect CA Password", 
                        f"The CA private key password is incorrect.\n\nError: {result.stderr}"
                    )
                    return
                else:
                    raise Exception(f"Failed to sign certificate: {result.stderr}")

            # Log successful completion
            openssl_logger.info(f"Certificate creation completed successfully for: {cert_name}")

            # Success
            QtWidgets.QMessageBox.information(
                self, "Certificate Created Successfully",
                f"Certificate '{cert_name}' has been created successfully!\n\n"
                f"Files created:\n"
                f"• Private Key: {key_file}\n"
                f"• Decrypted Key: {decrypted_key_file}\n"
                f"• Certificate Request: {csr_file}\n"
                f"• Certificate: {cert_file}\n\n"
                f"Subject: {subject}\n\n"
                f"OpenSSL commands logged to:\n{LOG_FILE}"
            )
            self.accept()

        except Exception as e:
            openssl_logger.error(f"Certificate creation failed for {cert_name}: {str(e)}")
            QtWidgets.QMessageBox.critical(
                self, "Certificate Creation Failed",
                f"Failed to create certificate '{cert_name}':\n\n{str(e)}\n\n"
                f"Check log file for details:\n{LOG_FILE}"
            )
        finally:
            # Clear passwords from memory for security
            ca_password = None
            key_password = None
            # Clear the password fields
            self.ca_password_edit.clear()
            self.key_password_edit.clear()

    def update_status(self, message):
        """Update status (you could add a progress bar here)"""
        QtWidgets.QApplication.processEvents()
        # For now, just process events to keep UI responsive

class CreateKeychainDialog(QtWidgets.QDialog):
    """Dialog for selecting root CA certificate for keychain creation"""
    
    def __init__(self, parent, cert_name):
        super().__init__(parent)
        self.cert_name = cert_name
        self.root_ca_path = ""
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the dialog UI"""
        self.setWindowTitle(f"Create Keychain for {self.cert_name}")
        self.setModal(True)
        self.resize(500, 200)
        
        layout = QtWidgets.QVBoxLayout()
        
        # Info label
        info_label = QtWidgets.QLabel(
            f"Creating keychain for certificate: {self.cert_name}\n\n"
            "Select the root CA certificate to complete the certificate chain:"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Root CA certificate selection group
        ca_group = QtWidgets.QGroupBox("Root CA Certificate")
        ca_layout = QtWidgets.QHBoxLayout()
        
        # Text box for certificate path
        self.root_ca_edit = QtWidgets.QLineEdit()
        self.root_ca_edit.setPlaceholderText("Path to root CA certificate file...")
        self.root_ca_edit.textChanged.connect(self.validate_certificate_path)
        ca_layout.addWidget(self.root_ca_edit)
        
        # Browse button
        self.browse_button = QtWidgets.QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_root_ca)
        ca_layout.addWidget(self.browse_button)
        
        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)
        
        # Button layout
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        
        self.ok_button = QtWidgets.QPushButton("OK")
        self.ok_button.setEnabled(False)  # Disabled until valid cert selected
        self.ok_button.clicked.connect(self.accept_dialog)
        button_layout.addWidget(self.ok_button)
        
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def browse_root_ca(self):
        """Open file dialog to select root CA certificate"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Root CA Certificate", "", 
            "Certificate Files (*.pem *.crt *.cer);;All Files (*)"
        )
        
        if file_path:
            self.root_ca_edit.setText(file_path)
            
    def validate_certificate_path(self):
        """Validate the certificate path and enable/disable OK button"""
        path = self.root_ca_edit.text().strip()
        
        # Check if path exists and is a file
        if path and os.path.exists(path) and os.path.isfile(path):
            # Basic validation - check if it looks like a certificate file
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    # Check for certificate markers
                    if "-----BEGIN CERTIFICATE-----" in content and "-----END CERTIFICATE-----" in content:
                        self.ok_button.setEnabled(True)
                        return
            except Exception:
                pass
        
        # If we get here, the path is invalid
        self.ok_button.setEnabled(False)
        
    def accept_dialog(self):
        """Accept dialog and store the root CA path"""
        self.root_ca_path = self.root_ca_edit.text().strip()
        self.accept()
        
    def get_root_ca_path(self):
        """Get the selected root CA path"""
        return self.root_ca_path

class CreateKeychainDialog(QtWidgets.QDialog):
    """Dialog for selecting root CA certificate for keychain creation"""
    
    def __init__(self, parent, cert_name):
        super().__init__(parent)
        self.cert_name = cert_name
        self.root_ca_path = ""
        self.last_validation_result = None
        self.setup_ui()
        self.load_saved_root_ca_path()  # Load saved path
        
    def setup_ui(self):
        """Set up the dialog UI"""
        self.setWindowTitle(f"Create Keychain for {self.cert_name}")
        self.setModal(True)
        
        # Fix geometry issues: use minimum size instead of fixed resize
        self.setMinimumSize(450, 250)
        self.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        
        layout = QtWidgets.QVBoxLayout()
        
        # Info label
        info_label = QtWidgets.QLabel(
            f"Creating keychain for certificate: {self.cert_name}\n\n"
            "Select the root CA certificate to complete the certificate chain:"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Root CA certificate selection group
        ca_group = QtWidgets.QGroupBox("Root CA Certificate")
        ca_layout = QtWidgets.QVBoxLayout()
        
        # Text box and browse button layout
        path_layout = QtWidgets.QHBoxLayout()
        self.root_ca_edit = QtWidgets.QLineEdit()
        self.root_ca_edit.setPlaceholderText("Path to root CA certificate file...")
        self.root_ca_edit.textChanged.connect(self.validate_certificate_path)
        path_layout.addWidget(self.root_ca_edit)
        
        self.browse_button = QtWidgets.QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_root_ca)
        path_layout.addWidget(self.browse_button)
        
        ca_layout.addLayout(path_layout)
        
        # Validation status label
        self.validation_label = QtWidgets.QLabel("")
        self.validation_label.setWordWrap(True)
        self.validation_label.setStyleSheet("QLabel { margin: 5px; padding: 5px; }")
        self.validation_label.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.MinimumExpanding)
        ca_layout.addWidget(self.validation_label)
        
        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)
        
        # Button layout
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        
        self.ok_button = QtWidgets.QPushButton("OK")
        self.ok_button.setEnabled(False)  # Disabled until valid cert selected
        self.ok_button.clicked.connect(self.accept_dialog)
        button_layout.addWidget(self.ok_button)
        
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def load_saved_root_ca_path(self):
        """Load and set the previously saved root CA path"""
        saved_path = load_root_ca_path()
        if saved_path and os.path.exists(saved_path):
            self.root_ca_edit.setText(saved_path)
            openssl_logger.info(f"Keychain dialog: Loaded saved root CA path: {saved_path}")
        elif saved_path:
            # Path was saved but file no longer exists
            openssl_logger.warning(f"Keychain dialog: Saved root CA path no longer exists: {saved_path}")
            
    def browse_root_ca(self):
        """Open file dialog to select root CA certificate"""
        # Start browse from directory of current path if available
        start_dir = ""
        current_path = self.root_ca_edit.text().strip()
        if current_path and os.path.exists(current_path):
            start_dir = os.path.dirname(current_path)
        
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Root CA Certificate", start_dir, 
            "Certificate Files (*.pem *.crt *.cer);;All Files (*)"
        )
        
        if file_path:
            self.root_ca_edit.setText(file_path)
            
    def validate_certificate_path(self):
        """Comprehensive certificate validation with OpenSSL and logging"""
        path = self.root_ca_edit.text().strip()
        
        # Clear previous validation state
        self.ok_button.setEnabled(False)
        self.last_validation_result = None
        
        # Basic path validation
        if not path:
            self.set_validation_message("", "")
            return
            
        if not os.path.exists(path):
            self.set_validation_message("File does not exist.", "error")
            openssl_logger.warning(f"Keychain dialog: Root CA file does not exist: {path}")
            return
            
        if not os.path.isfile(path):
            self.set_validation_message("Path is not a file.", "error")
            openssl_logger.warning(f"Keychain dialog: Root CA path is not a file: {path}")
            return
        
        # Check if it's a keychain file (not allowed for root CA)
        filename = os.path.basename(path)
        if filename.startswith("keychain."):
            self.set_validation_message("Root CA cannot be a keychain file.", "error")
            openssl_logger.warning(f"Keychain dialog: Root CA file is a keychain (not allowed): {path}")
            return
        
        # Basic file content validation
        try:
            with open(path, 'r') as f:
                content = f.read()
                if not ("-----BEGIN CERTIFICATE-----" in content and "-----END CERTIFICATE-----" in content):
                    self.set_validation_message("File does not contain a valid certificate format.", "error")
                    openssl_logger.warning(f"Keychain dialog: Root CA file missing certificate markers: {path}")
                    return
        except Exception as e:
            self.set_validation_message(f"Cannot read file: {str(e)}", "error")
            openssl_logger.error(f"Keychain dialog: Cannot read Root CA file {path}: {str(e)}")
            return
        
        # Comprehensive OpenSSL validation
        openssl_logger.info(f"Keychain dialog: Validating Root CA certificate: {path}")
        self.validate_certificate_with_openssl(path)
        
    def validate_certificate_with_openssl(self, cert_path):
        """Validate certificate using OpenSSL commands with comprehensive checks"""
        try:
            # Test 1: Basic certificate parsing
            openssl_logger.info(f"Keychain dialog: Running basic certificate validation on: {cert_path}")
            result = run_openssl_command([
                "openssl", "x509", "-in", cert_path, "-noout", "-text"
            ], description=f"Validate Root CA certificate format: {os.path.basename(cert_path)}")
            
            if result.returncode != 0:
                self.set_validation_message("Invalid certificate format or corrupted file.", "error")
                openssl_logger.error(f"Keychain dialog: Root CA certificate format validation failed: {cert_path}")
                openssl_logger.error(f"OpenSSL error: {result.stderr}")
                return
                
            # Test 2: Get certificate details (subject, issuer, expiry)
            openssl_logger.info(f"Keychain dialog: Getting certificate details for: {cert_path}")
            result = run_openssl_command([
                "openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate"
            ], description=f"Get Root CA certificate details: {os.path.basename(cert_path)}")
            
            if result.returncode != 0:
                self.set_validation_message("Cannot read certificate details.", "error")
                openssl_logger.error(f"Keychain dialog: Cannot read Root CA certificate details: {cert_path}")
                return
                
            # Parse certificate information
            output = result.stdout
            subject = issuer = None
            enddate_str = None
            
            for line in output.splitlines():
                if line.startswith("subject="):
                    subject = line[len("subject="):].strip()
                elif line.startswith("issuer="):
                    issuer = line[len("issuer="):].strip()
                elif line.startswith("notAfter="):
                    enddate_str = line[len("notAfter="):].strip()
            
            openssl_logger.info(f"Keychain dialog: Root CA certificate subject: {subject}")
            openssl_logger.info(f"Keychain dialog: Root CA certificate issuer: {issuer}")
            openssl_logger.info(f"Keychain dialog: Root CA certificate expires: {enddate_str}")
            
            # Test 3: Check expiry date
            expiry = None
            if enddate_str:
                try:
                    expiry = datetime.strptime(enddate_str, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=timezone.utc)  # Make timezone-aware
                    now = datetime.now(timezone.utc)

                    if expiry <= now:
                        self.set_validation_message("Certificate has expired and cannot be used.", "error")
                        openssl_logger.error(f"Keychain dialog: Root CA certificate expired on {enddate_str}: {cert_path}")
                        return
                    elif expiry <= (now + timedelta(days=30)):
                        # Certificate expires soon - warn but allow
                        openssl_logger.warning(f"Keychain dialog: Root CA certificate expires soon ({enddate_str}): {cert_path}")
                        
                except Exception as e:
                    openssl_logger.warning(f"Keychain dialog: Could not parse expiry date '{enddate_str}': {str(e)}")
            
            # Test 4: Check if it's a multi-certificate file (chain)
            cert_count = 0
            try:
                with open(cert_path, 'r') as f:
                    content = f.read()
                    cert_count = content.count("-----BEGIN CERTIFICATE-----")
            except Exception:
                cert_count = 1  # Assume single if can't count
            
            if cert_count > 1:
                self.set_validation_message("Root CA file contains multiple certificates (chain). Please select a single root CA certificate.", "error")
                openssl_logger.error(f"Keychain dialog: Root CA file contains {cert_count} certificates (should be single): {cert_path}")
                return
                
            # Test 5: Verify it's likely a root CA (self-signed)
            is_self_signed = subject and issuer and (subject == issuer)
            if not is_self_signed and subject and issuer:
                # Not self-signed - warn but allow (could be intermediate used as root)
                openssl_logger.warning(f"Keychain dialog: Certificate is not self-signed (Subject: {subject}, Issuer: {issuer})")
                openssl_logger.warning(f"Keychain dialog: This may be an intermediate certificate, not a root CA: {cert_path}")
                
            # All validations passed
            self.last_validation_result = {
                'path': cert_path,
                'subject': subject,
                'issuer': issuer,
                'expiry': expiry,
                'is_self_signed': is_self_signed
            }
            
            # Set success message
            if is_self_signed:
                status_msg = f"✓ Valid root CA certificate\nSubject: {subject}"
            else:
                status_msg = f"⚠ Valid certificate (may be intermediate)\nSubject: {subject}\nIssuer: {issuer}"
                
            if expiry and expiry <= (datetime.now(timezone.utc) + timedelta(days=30)):
                status_msg += f"\n⚠ Expires soon: {expiry.strftime('%Y-%m-%d')}"
            elif expiry:
                status_msg += f"\nExpires: {expiry.strftime('%Y-%m-%d')}"
                
            self.set_validation_message(status_msg, "success" if is_self_signed else "warning")
            self.ok_button.setEnabled(True)
            
            openssl_logger.info(f"Keychain dialog: Root CA certificate validation successful: {cert_path}")
            
        except Exception as e:
            self.set_validation_message(f"Validation error: {str(e)}", "error")
            openssl_logger.error(f"Keychain dialog: Root CA certificate validation exception for {cert_path}: {str(e)}")
            
    def set_validation_message(self, message, status):
        """Set validation message with appropriate styling"""
        if status == "success":
            style = "QLabel { color: green; background-color: #e8f5e8; border: 1px solid green; border-radius: 3px; }"
            # Save the valid root CA path when validation succeeds
            if self.last_validation_result:
                save_root_ca_path(self.last_validation_result['path'])
                openssl_logger.info(f"Keychain dialog: Saved root CA path to settings: {self.last_validation_result['path']}")
        elif status == "warning":
            style = "QLabel { color: #cc6600; background-color: #fff3cd; border: 1px solid #cc6600; border-radius: 3px; }"
            # Also save for warnings (valid but with issues)
            if self.last_validation_result:
                save_root_ca_path(self.last_validation_result['path'])
        elif status == "error":
            style = "QLabel { color: red; background-color: #f8d7da; border: 1px solid red; border-radius: 3px; }"
        else:
            style = "QLabel { color: gray; }"
            
        self.validation_label.setText(message)
        self.validation_label.setStyleSheet(style)
        
        # Ensure the dialog adjusts its size naturally
        self.adjustSize()
        
    def accept_dialog(self):
        """Accept dialog and store the root CA path"""
        if self.last_validation_result:
            self.root_ca_path = self.last_validation_result['path']
            openssl_logger.info(f"Keychain dialog: Root CA certificate accepted: {self.root_ca_path}")
            self.accept()
        else:
            openssl_logger.warning("Keychain dialog: Accept attempted without valid certificate")
            
    def get_root_ca_path(self):
        """Get the selected root CA path"""
        return self.root_ca_path
        
    def get_validation_result(self):
        """Get the full validation result"""
        return self.last_validation_result

class CAManager(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OpenSSL CA Manager")

        # Create central widget
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)

        outer_layout = QtWidgets.QVBoxLayout()

        # Top controls layout
        top_layout = QtWidgets.QHBoxLayout()

        self.configPathEdit = QtWidgets.QLineEdit()
        self.configPathEdit.setPlaceholderText("Path to openssl.cnf")

        last_config = load_last_config_path()
        if last_config:
            self.configPathEdit.setText(last_config)

        top_layout.addWidget(self.configPathEdit)

        self.browseButton = QtWidgets.QPushButton("Browse...")
        top_layout.addWidget(self.browseButton)
        self.browseButton.clicked.connect(self.browse_file)

        self.loadButton = QtWidgets.QPushButton("Load CA Config & Certs")
        top_layout.addWidget(self.loadButton)
        self.loadButton.clicked.connect(self.load_config_and_certs)

        outer_layout.addLayout(top_layout)

        # Filter controls layout
        filter_layout = QtWidgets.QHBoxLayout()

        self.hideExpiredCheckbox = QtWidgets.QCheckBox("Hide Expired Certificates")
        self.hideExpiredCheckbox.stateChanged.connect(self.filter_certificates)
        filter_layout.addWidget(self.hideExpiredCheckbox)

        # Add debug label to show filter stats
        self.filterStatsLabel = QtWidgets.QLabel("No certificates loaded")
        filter_layout.addWidget(self.filterStatsLabel)

        filter_layout.addStretch()  # Push checkbox to left
        outer_layout.addLayout(filter_layout)

        # Certificate list and buttons layout
        cert_list_layout = QtWidgets.QHBoxLayout()

        self.certsTree = QtWidgets.QTreeWidget()
        self.certsTree.setColumnCount(5)
        self.certsTree.setHeaderLabels(["Status", "File", "Subject", "Issuer", "Expiry"])
        self.certsTree.itemSelectionChanged.connect(self.on_cert_selection_changed)
        cert_list_layout.addWidget(self.certsTree)

        # Certificate action buttons (vertical layout on the right)
        buttons_layout = QtWidgets.QVBoxLayout()

        self.newCertButton = QtWidgets.QPushButton("New Certificate")
        self.newCertButton.setEnabled(False)  # Disabled until config loaded
        self.newCertButton.setToolTip("Create a new certificate (requires CA config)")
        self.newCertButton.clicked.connect(self.new_certificate)
        buttons_layout.addWidget(self.newCertButton)

        # Add a separator line
        separator = QtWidgets.QFrame()
        separator.setFrameShape(QtWidgets.QFrame.HLine)
        separator.setFrameShadow(QtWidgets.QFrame.Sunken)
        buttons_layout.addWidget(separator)

        self.renewButton = QtWidgets.QPushButton("Renew")
        self.renewButton.setEnabled(False)  # Disabled until config loaded
        self.renewButton.setToolTip("Renew the selected certificate (requires CA config)")
        self.renewButton.clicked.connect(self.renew_certificate)
        buttons_layout.addWidget(self.renewButton)

        self.revokeButton = QtWidgets.QPushButton("Revoke")
        self.revokeButton.setEnabled(False)  # Disabled until config loaded
        self.revokeButton.setToolTip("Revoke the selected certificate (requires CA config)")
        self.revokeButton.clicked.connect(self.revoke_certificate)
        buttons_layout.addWidget(self.revokeButton)

        self.keychainButton = QtWidgets.QPushButton("Create Keychain")
        self.keychainButton.setEnabled(False) # Disabled until valid cert selected
        self.keychainButton.setToolTip("Create keychain file (selected cert + intermediate + root CA)")
        self.keychainButton.clicked.connect(self.create_keychain)
        buttons_layout.addWidget(self.keychainButton)

        buttons_layout.addStretch()  # Push buttons to top
        cert_list_layout.addLayout(buttons_layout)

        # Main content splitter
        self.main_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Add certificate list with buttons to splitter
        cert_widget = QtWidgets.QWidget()
        cert_widget.setLayout(cert_list_layout)
        self.main_splitter.addWidget(cert_widget)
        self.main_splitter.setStretchFactor(0, 2)

        self.details_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        self.certDetailsText = QtWidgets.QTextEdit()
        self.certDetailsText.setReadOnly(True)
        self.certDetailsText.setPlaceholderText("Certificate Details")
        self.details_splitter.addWidget(self.certDetailsText)

        self.configDetailsText = QtWidgets.QTextEdit()
        self.configDetailsText.setReadOnly(True)
        self.configDetailsText.setPlaceholderText("Configuration Sections")
        self.details_splitter.addWidget(self.configDetailsText)

        self.main_splitter.addWidget(self.details_splitter)
        self.main_splitter.setStretchFactor(1, 3)

        outer_layout.addWidget(self.main_splitter)
        central_widget.setLayout(outer_layout)

        self.icons = {
            "valid": self.style().standardIcon(QtWidgets.QStyle.SP_DialogApplyButton),
            "warning": self.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxWarning),
            "expired": self.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxCritical),
            "invalid": self.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxQuestion),
            "chain": self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView)
        }

        self.config = None
        self.dir_path = '.'
        self.certs_dir = 'certs'
        self.all_cert_items = []  # Store all certificate items for filtering
        self.ca_config_loaded = False  # Track if CA config is loaded

        self.certsTree.itemClicked.connect(self.show_cert_details)

        # Add menu bar
        self.create_menu_bar()

    def create_menu_bar(self):
        """Create menu bar with logging options"""
        menubar = self.menuBar()
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        # View log action
        view_log_action = QtWidgets.QAction('View OpenSSL Log', self)
        view_log_action.triggered.connect(self.view_openssl_log)
        tools_menu.addAction(view_log_action)
        
        # Clear log action
        clear_log_action = QtWidgets.QAction('Clear OpenSSL Log', self)
        clear_log_action.triggered.connect(self.clear_openssl_log)
        tools_menu.addAction(clear_log_action)

    def view_openssl_log(self):
        """Show OpenSSL log in a dialog"""
        if not os.path.exists(LOG_FILE):
            QtWidgets.QMessageBox.information(
                self, 'No Log File', 
                f'OpenSSL log file does not exist yet:\n{LOG_FILE}'
            )
            return
        
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                log_content = f.read()
            
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle('OpenSSL Commands Log')
            dialog.resize(800, 600)
            
            layout = QtWidgets.QVBoxLayout()
            
            # Add file path label at the top
            path_label = QtWidgets.QLabel(f"Log File: {LOG_FILE}")
            path_label.setStyleSheet("font-weight: bold; margin-bottom: 5px;")
            layout.addWidget(path_label)
            
            text_edit = QtWidgets.QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(log_content)
            text_edit.setFont(QtGui.QFont("Courier", 9))
            layout.addWidget(text_edit)
            
            button_layout = QtWidgets.QHBoxLayout()
            
            # Add button to open log file location
            open_location_button = QtWidgets.QPushButton('Open File Location')
            open_location_button.clicked.connect(lambda: self.open_file_location(LOG_FILE))
            button_layout.addWidget(open_location_button)
            
            button_layout.addStretch()
            
            close_button = QtWidgets.QPushButton('Close')
            close_button.clicked.connect(dialog.accept)
            button_layout.addWidget(close_button)
            
            layout.addLayout(button_layout)
            dialog.setLayout(layout)
            
            dialog.exec_()
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self, 'Error Reading Log', 
                f'Failed to read log file:\n{str(e)}'
            )

    def open_file_location(self, file_path):
        """Open the file location in the system file manager"""
        try:
            import platform
            system = platform.system()
            
            if system == "Windows":
                os.startfile(os.path.dirname(file_path))
            elif system == "Darwin":  # macOS
                subprocess.run(["open", os.path.dirname(file_path)])
            else:  # Linux and others
                subprocess.run(["xdg-open", os.path.dirname(file_path)])
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self, 'Cannot Open Location',
                f'Failed to open file location:\n{str(e)}\n\nFile location: {os.path.dirname(file_path)}'
            )

    def clear_openssl_log(self):
        """Clear the OpenSSL log file"""
        reply = QtWidgets.QMessageBox.question(
            self, 'Clear Log File',
            f'Are you sure you want to clear the OpenSSL log file?\n\n{LOG_FILE}',
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        
        if reply == QtWidgets.QMessageBox.Yes:
            try:
                open(LOG_FILE, 'w').close()  # Clear the file
                QtWidgets.QMessageBox.information(
                    self, 'Log Cleared', 
                    f'OpenSSL log file has been cleared successfully:\n{LOG_FILE}'
                )
            except Exception as e:
                QtWidgets.QMessageBox.critical(
                    self, 'Error Clearing Log', 
                    f'Failed to clear log file:\n{str(e)}'
                )

    def closeEvent(self, event):
        save_last_config_path(self.configPathEdit.text())
        event.accept()

    def browse_file(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select OpenSSL CA Config File", "", "Config Files (*.cnf *.conf);;All Files (*)"
        )

        if file_path:
            self.configPathEdit.setText(file_path)

    def set_ca_buttons_enabled(self, enabled):
        """Enable or disable all CA-related buttons"""
        self.newCertButton.setEnabled(enabled)
        if not enabled:
            # If CA config not loaded, disable all buttons
            self.renewButton.setEnabled(False)
            self.revokeButton.setEnabled(False)
            self.keychainButton.setEnabled(False)
        # If enabled, let on_cert_selection_changed handle button states based on selection

    def load_config_and_certs(self):
        config_path = self.configPathEdit.text().strip()

        try:
            # Use the enhanced config parser that returns both config and tree
            config, tree = parse_openssl_config(config_path)
            
            ca_section = find_section(config, 'ca')
            if not ca_section:
                raise Exception('CA section not found in config.')

            config_dir = os.path.dirname(os.path.abspath(config_path))

            # Get base directory
            dir_raw = clean_config_value(config[ca_section].get('dir', '.'))
            if not os.path.isabs(dir_raw):
                dir_path = os.path.normpath(os.path.join(config_dir, dir_raw))
            else:
                dir_path = os.path.normpath(dir_raw)

            # Create variables dictionary for proper path resolution
            variables = {
                'dir': dir_path,
                'config_dir': config_dir
            }

            # Resolve certs directory properly
            certs_raw = clean_config_value(config[ca_section].get('certs', 'certs'))
            certs_dir = resolve_path(certs_raw, variables)

            if not os.path.isabs(certs_dir):
                certs_dir = os.path.join(dir_path, certs_dir)

            # Log the resolved paths for debugging
            openssl_logger.info(f"Config loading - Base dir: {dir_path}")
            openssl_logger.info(f"Config loading - Certs dir raw: {certs_raw}")
            openssl_logger.info(f"Config loading - Certs dir resolved: {certs_dir}")

            self.dir_path = dir_path
            self.certs_dir = certs_dir
            self.config = config
            self.config_tree = tree  # Store the enhanced tree structure
            self.ca_sections = get_all_linked_sections(config, ca_section)

            # Mark CA config as successfully loaded
            self.ca_config_loaded = True

            # Enable CA-related buttons
            self.set_ca_buttons_enabled(True)

            self.load_certificates_list()
            save_last_config_path(config_path)

        except Exception as e:
            self.certDetailsText.setText(f"Error loading config: {e}")
            self.configDetailsText.setText("")

            # Mark CA config as not loaded and disable buttons
            self.ca_config_loaded = False
            self.set_ca_buttons_enabled(False)

    def load_certificates_list(self):
        self.certsTree.clear()
        self.all_cert_items = []

        if not os.path.isdir(self.certs_dir):
            self.certDetailsText.setText(f"Certificates directory not found: {self.certs_dir}")
            self.filterStatsLabel.setText("No certificates directory")
            return

        cert_files = [f for f in os.listdir(self.certs_dir) if f.lower().endswith('.pem')]

        if not cert_files:
            self.certDetailsText.setText(f"No .pem files found in: {self.certs_dir}")
            self.filterStatsLabel.setText("No .pem files found")
            return

        for cert_file in cert_files:
            cert_path = os.path.join(self.certs_dir, cert_file)
            cert_type = detect_cert_type(cert_path)
            info = get_certificate_info(cert_path)

            has_error = "error" in info
            if has_error:
                status = "invalid"
                subject = issuer = expiry_str = f"Error: {info['error']}"
            else:
                status = certificate_status_icon(info["expiry"], cert_type, has_error)
                subject = info.get("subject", "N/A")
                issuer = info.get("issuer", "N/A")
                expiry = info.get("expiry", None)
                expiry_str = expiry.strftime("%Y-%m-%d %H:%M:%S") if expiry else "N/A"

                # For chains, show additional info
                if cert_type == "chain":
                    certificates = extract_certificates(cert_path)
                    subject = f"{subject} (Chain: {len(certificates)} certs)"

            # Store certificate item data
            cert_item = CertificateItem(
                cert_path, cert_type, status, subject, issuer, expiry_str,
                self.icons.get(status, self.icons["invalid"])
            )
            self.all_cert_items.append(cert_item)

        # Apply current filter
        self.filter_certificates()

    def filter_certificates(self):
        """Filter certificates based on checkbox states"""
        self.certsTree.clear()

        hide_expired = self.hideExpiredCheckbox.isChecked()

        total_certs = len(self.all_cert_items)
        expired_count = sum(1 for item in self.all_cert_items if item.status == "expired")
        invalid_count = sum(1 for item in self.all_cert_items if item.status == "invalid")
        shown_count = 0

        for cert_item in self.all_cert_items:
            # Check if item should be hidden
            if hide_expired and cert_item.status == "expired":
                continue

            shown_count += 1

            # Create new tree item
            item = QtWidgets.QTreeWidgetItem()
            item.setIcon(0, cert_item.icon)
            item.setText(1, cert_item.cert_file)
            item.setText(2, cert_item.subject)
            item.setText(3, cert_item.issuer)
            item.setText(4, cert_item.expiry_str)

            item.setData(0, QtCore.Qt.UserRole, cert_item.cert_path)
            item.setData(1, QtCore.Qt.UserRole, cert_item.cert_type)
            item.setData(2, QtCore.Qt.UserRole, cert_item.status)

            # Add item to tree
            self.certsTree.addTopLevelItem(item)

        # Update stats label
        if hide_expired:
            self.filterStatsLabel.setText(f"Showing {shown_count}/{total_certs} certs ({expired_count} expired hidden, {invalid_count} invalid)")
        else:
            self.filterStatsLabel.setText(f"Showing {shown_count}/{total_certs} certs ({expired_count} expired, {invalid_count} invalid)")

    def on_cert_selection_changed(self):
        """Handle certificate selection changes to enable/disable buttons"""
        # Only handle selection if CA config is loaded
        if not self.ca_config_loaded:
            return

        selected_items = self.certsTree.selectedItems()
        if len(selected_items) == 1:
            item = selected_items[0]
            cert_type = item.data(1, QtCore.Qt.UserRole)
            cert_status = item.data(2, QtCore.Qt.UserRole)
            cert_file = item.text(1)

            # Enable buttons only for single certificates, not chains
            is_single_cert = cert_type == "single"
            
            # Renew button: active for single certificates (regardless of expiry)
            self.renewButton.setEnabled(is_single_cert)
            
            # Revoke button: active only for single, non-expired certificates
            is_non_expired = cert_status not in ["expired", "invalid"]
            self.revokeButton.setEnabled(is_single_cert and is_non_expired)
            
            # Keychain button: active only for valid single certificates that aren't already keychains
            is_valid_cert = cert_status in ["valid", "warning"]  # Include warning (expiring soon)
            is_not_keychain = not cert_file.startswith("keychain.")
            self.keychainButton.setEnabled(is_single_cert and is_valid_cert and is_not_keychain)
        else:
            # No selection or multiple selections - disable all action buttons
            self.renewButton.setEnabled(False)
            self.revokeButton.setEnabled(False)
            self.keychainButton.setEnabled(False)

    def new_certificate(self):
        """Handle new certificate creation"""
        if not self.ca_config_loaded:
            QtWidgets.QMessageBox.warning(
                self, 'No CA Configuration',
                'Please load a CA configuration file first.'
            )
            return

        # Open new certificate dialog
        dialog = NewCertificateDialog(
            self,
            self.config,
            self.configPathEdit.text().strip(),
            self.ca_sections
        )

        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            # Refresh certificate list to show new certificate
            self.load_certificates_list()

    def renew_certificate(self):
        """Handle certificate renewal with comprehensive logging"""
        if not self.ca_config_loaded:
            QtWidgets.QMessageBox.warning(
                self, 'No CA Configuration',
                'Please load a CA configuration file first.'
            )
            return

        selected_items = self.certsTree.selectedItems()
        if len(selected_items) != 1:
            return

        item = selected_items[0]
        cert_path = item.data(0, QtCore.Qt.UserRole)
        cert_status = item.data(2, QtCore.Qt.UserRole)
        cert_file = os.path.basename(cert_path)
        cert_name = cert_file.replace('.cert.pem', '')

        # Show confirmation dialog
        reply = QtWidgets.QMessageBox.question(
            self, 'Renew Certificate',
            f'Are you sure you want to renew certificate "{cert_file}"?\n'
            'This will generate a new certificate with extended validity period.',
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        
        if reply != QtWidgets.QMessageBox.Yes:
            openssl_logger.info(f"Certificate renewal cancelled by user for: {cert_name}")
            return

        ca_password = None
        try:
            # Log the start of renewal with separator
            openssl_logger.info("=" * 80)
            openssl_logger.info(f"OPERATION: Certificate renewal for {cert_name}")
            openssl_logger.info(f"CERTIFICATE FILE: {cert_path}")
            openssl_logger.info(f"CERTIFICATE STATUS: {cert_status}")
            
            # Look for existing CSR file
            config_file = self.configPathEdit.text().strip()
            config_dir = os.path.dirname(os.path.abspath(config_file))
            
            # Get CSR directory from config
            ca_section = find_section(self.config, 'ca')
            if not ca_section:
                raise Exception('CA section not found in config.')
            
            default_ca_name = clean_config_value(self.config[ca_section].get('default_ca', ''))
            default_ca_section = find_section(self.config, default_ca_name)
            if not default_ca_section:
                raise Exception(f'Default CA section "{default_ca_name}" not found in config.')
            
            # Get and resolve CSR directory
            dir_raw = clean_config_value(self.config[default_ca_section].get('dir', '.'))
            if not os.path.isabs(dir_raw):
                base_dir = os.path.normpath(os.path.join(config_dir, dir_raw))
            else:
                base_dir = os.path.normpath(dir_raw)
            
            variables = {
                'dir': base_dir,
                'config_dir': config_dir
            }
            
            csr_dir_raw = clean_config_value(self.config[default_ca_section].get('new_certs_dir', 'newcerts'))
            # Often CSRs are in a 'csr' subdirectory, but let's check the actual config
            # Try common CSR directory patterns
            possible_csr_dirs = ['csr', 'csrs', 'requests', 'req', base_dir]
            
            openssl_logger.info(f"Base directory: {base_dir}")
            openssl_logger.info(f"Looking for CSR file for certificate: {cert_name}")
            
            csr_file = None
            for csr_dir_name in possible_csr_dirs:
                if csr_dir_name == base_dir:
                    test_csr_dir = base_dir
                else:
                    test_csr_dir = os.path.join(base_dir, csr_dir_name)
                
                test_csr_path = os.path.join(test_csr_dir, f"{cert_name}.csr.pem")
                openssl_logger.info(f"Checking for CSR at: {test_csr_path}")
                
                if os.path.exists(test_csr_path):
                    csr_file = test_csr_path
                    openssl_logger.info(f"Found CSR file: {csr_file}")
                    break
            
            if not csr_file:
                openssl_logger.error(f"CSR file not found for certificate: {cert_name}")
                openssl_logger.error(f"Searched in directories: {possible_csr_dirs}")
                QtWidgets.QMessageBox.warning(
                    self, 'CSR Not Found',
                    f'Certificate Signing Request not found for "{cert_name}".\n'
                    'Cannot renew certificate without original CSR.\n\n'
                    f'Searched in: {base_dir}/[csr|csrs|requests|req]/'
                )
                return
            
            # Get CA private key password
            openssl_logger.info("Requesting CA private key password from user")
            ca_password, ok = QtWidgets.QInputDialog.getText(
                self, 'CA Private Key Password',
                'Enter the CA private key password for renewal:',
                QtWidgets.QLineEdit.Password
            )
            
            if not ok:
                openssl_logger.info(f"Certificate renewal cancelled by user (password dialog) for: {cert_name}")
                return  # User cancelled
            
            openssl_logger.info("CA password provided by user")
            
            # Create backup of current certificate
            backup_file = f"{cert_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            openssl_logger.info(f"Creating backup of current certificate: {backup_file}")
            
            import shutil
            shutil.copy2(cert_path, backup_file)
            openssl_logger.info(f"Backup created successfully: {backup_file}")
            
            # Prepare OpenSSL command for renewal
            sign_cmd = [
                "openssl", "ca", 
                "-config", config_file,
                "-days", "375",
                "-notext", 
                "-md", "sha256",
                "-in", csr_file,
                "-out", cert_path,
                "-passin", f"pass:{ca_password}",
                "-batch"
            ]
            
            openssl_logger.info(f"Executing certificate renewal command")
            openssl_logger.info(f"Command: {' '.join(sign_cmd[:sign_cmd.index('-passin')] + ['-passin', 'pass:***'])}")
            openssl_logger.info(f"Working directory: {base_dir}")
            
            # Execute the OpenSSL command
            result = run_openssl_command(
                sign_cmd, 
                cwd=base_dir,
                description=f"Renew certificate for {cert_name}"
            )
            
            if result.returncode == 0:
                openssl_logger.info("=" * 80)
                openssl_logger.info(f"Certificate renewal completed successfully for: {cert_name}")
                openssl_logger.info(f"Backup file: {backup_file}")
                openssl_logger.info(f"New certificate: {cert_path}")
                openssl_logger.info("=" * 80)
                openssl_logger.info("")  # Empty line for separation
                
                QtWidgets.QMessageBox.information(
                    self, 'Certificate Renewed Successfully',
                    f'Certificate "{cert_file}" has been successfully renewed!\n\n'
                    f'Original certificate backed up to:\n{backup_file}\n\n'
                    f'New certificate saved to:\n{cert_path}\n\n'
                    f'Commands logged to:\n{LOG_FILE}'
                )
                
                # Refresh certificate list to show updated certificate
                openssl_logger.info(f"Refreshing certificate list to show renewed certificate: {cert_name}")
                self.load_certificates_list()
            else:
                # Renewal failed - restore backup
                openssl_logger.error(f"Certificate renewal failed for: {cert_name}")
                openssl_logger.error(f"OpenSSL return code: {result.returncode}")
                openssl_logger.error(f"OpenSSL error output: {result.stderr}")
                
                openssl_logger.info(f"Restoring backup certificate: {backup_file} -> {cert_path}")
                shutil.move(backup_file, cert_path)
                openssl_logger.info("Backup restored successfully")
                
                # Check for common password-related errors
                if "bad decrypt" in result.stderr.lower() or "wrong password" in result.stderr.lower():
                    QtWidgets.QMessageBox.critical(
                        self, 'Incorrect Password',
                        f'Incorrect CA private key password.\n\n'
                        f'Error: {result.stderr}\n\n'
                        'Original certificate has been restored.'
                    )
                else:
                    QtWidgets.QMessageBox.critical(
                        self, 'Renewal Failed',
                        f'Failed to renew certificate "{cert_file}".\n\n'
                        f'Error: {result.stderr}\n\n'
                        'Original certificate has been restored.\n\n'
                        f'Check log file: {LOG_FILE}'
                    )
                    
        except Exception as e:
            openssl_logger.error("=" * 80)
            openssl_logger.error(f"Certificate renewal failed for {cert_name}: {str(e)}")
            openssl_logger.error("=" * 80)
            openssl_logger.error("")  # Empty line for separation
            
            QtWidgets.QMessageBox.critical(
                self, 'Renewal Error',
                f'An error occurred while renewing certificate "{cert_file}":\n\n{str(e)}\n\n'
                f'Check log file: {LOG_FILE}'
            )
            
        finally:
            # Clear password from memory for security
            ca_password = None
            openssl_logger.info(f"Certificate renewal process completed for: {cert_name}")

    def revoke_certificate(self):
        """Handle certificate revocation"""
        if not self.ca_config_loaded:
            QtWidgets.QMessageBox.warning(
                self, 'No CA Configuration',
                'Please load a CA configuration file first.'
            )
            return

        selected_items = self.certsTree.selectedItems()
        if len(selected_items) != 1:
            return

        item = selected_items[0]
        cert_path = item.data(0, QtCore.Qt.UserRole)
        cert_status = item.data(2, QtCore.Qt.UserRole)
        cert_file = os.path.basename(cert_path)

        # Double check the certificate is not expired
        if cert_status in ["expired", "invalid"]:
            QtWidgets.QMessageBox.warning(
                self, 'Cannot Revoke Certificate',
                f'Cannot revoke certificate "{cert_file}" because it is {cert_status}.'
            )
            return

        # Get CA private key password
        password, ok = QtWidgets.QInputDialog.getText(
            self, 'CA Private Key Password',
            'Enter the CA private key password:',
            QtWidgets.QLineEdit.Password
        )

        if not ok:
            return  # User cancelled

        # Show confirmation dialog with command info
        config_file = self.configPathEdit.text().strip()
        command = f"openssl ca -revoke {cert_path} -config {config_file} -passin pass:****"

        reply = QtWidgets.QMessageBox.question(
            self, 'Revoke Certificate',
            f'Are you sure you want to revoke certificate "{cert_file}"?\n\n'
            f'Command to execute:\n{command}\n\n'
            'This action cannot be undone!',
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )

        if reply == QtWidgets.QMessageBox.Yes:
            try:
                openssl_logger.info(f"Starting certificate revocation for: {cert_file}")
                
                # Execute the OpenSSL revoke command with password
                result = run_openssl_command(
                    ["openssl", "ca", "-revoke", cert_path, "-config", config_file, "-passin", f"pass:{password}"],
                    cwd=os.path.dirname(config_file),
                    description=f"Revoke certificate {cert_file}"
                )

                # Clear password from memory
                password = None

                if result.returncode == 0:
                    openssl_logger.info(f"Certificate revocation completed successfully for: {cert_file}")
                    # Success
                    QtWidgets.QMessageBox.information(
                        self, 'Certificate Revoked Successfully',
                        f'Certificate "{cert_file}" has been successfully revoked.\n\n'
                        f'Output:\n{result.stdout}\n\n'
                        'The certificate has been added to the revocation list.\n\n'
                        f'Commands logged to:\n{LOG_FILE}'
                    )
                    # Refresh the certificate list to update status
                    self.load_certificates_list()
                else:
                    # Error occurred
                    error_msg = result.stderr
                    if "bad decrypt" in error_msg.lower() or "wrong password" in error_msg.lower():
                        QtWidgets.QMessageBox.critical(
                            self, 'Incorrect Password',
                            f'Incorrect CA private key password.\n\n'
                            f'Error: {error_msg}'
                        )
                    else:
                        QtWidgets.QMessageBox.critical(
                            self, 'Revocation Failed',
                            f'Failed to revoke certificate "{cert_file}".\n\n'
                            f'Error:\n{error_msg}\n\n'
                            f'Check log file: {LOG_FILE}'
                        )

            except Exception as e:
                openssl_logger.error(f"Certificate revocation failed for {cert_file}: {str(e)}")
                QtWidgets.QMessageBox.critical(
                    self, 'Revocation Error',
                    f'An error occurred while revoking certificate "{cert_file}":\n\n'
                    f'{str(e)}\n\n'
                    f'Check log file: {LOG_FILE}'
                )
            finally:
                # Ensure password is cleared from memory
                password = None

    def create_keychain(self):
        """Handle keychain creation with custom dialog and comprehensive logging"""
        if not self.ca_config_loaded:
            QtWidgets.QMessageBox.warning(
                self, 'No CA Configuration',
                'Please load a CA configuration file first.'
            )
            return

        selected_items = self.certsTree.selectedItems()
        if len(selected_items) != 1:
            return

        item = selected_items[0]
        cert_path = item.data(0, QtCore.Qt.UserRole)
        cert_status = item.data(2, QtCore.Qt.UserRole)
        cert_file = os.path.basename(cert_path)
        cert_name = cert_file.replace('.cert.pem', '')

        # Double check the certificate is valid and not already a keychain
        if cert_status not in ["valid", "warning"]:
            openssl_logger.warning(f"Keychain creation refused - invalid certificate status: {cert_file} ({cert_status})")
            QtWidgets.QMessageBox.warning(
                self, 'Invalid Certificate',
                f'Cannot create keychain for certificate "{cert_file}" because it is {cert_status}.'
            )
            return

        if cert_file.startswith("keychain."):
            openssl_logger.warning(f"Keychain creation refused - already a keychain: {cert_file}")
            QtWidgets.QMessageBox.warning(
                self, 'Already a Keychain',
                f'The selected file "{cert_file}" is already a keychain file.'
            )
            return

        # Show custom dialog to get root CA certificate
        openssl_logger.info(f"Starting keychain creation process for: {cert_name}")
        openssl_logger.info(f"Selected certificate: {cert_path}")
        
        dialog = CreateKeychainDialog(self, cert_name)
        if dialog.exec_() != QtWidgets.QDialog.Accepted:
            openssl_logger.info(f"Keychain creation cancelled by user for: {cert_name}")
            return
        
        root_ca_path = dialog.get_root_ca_path()
        openssl_logger.info(f"Root CA certificate selected: {root_ca_path}")

        try:
            # Log the start of keychain creation
            openssl_logger.info("=" * 80)
            openssl_logger.info(f"OPERATION: Create keychain for {cert_name}")
            openssl_logger.info(f"CERTIFICATE: {cert_path}")
            openssl_logger.info(f"ROOT CA: {root_ca_path}")
            
            # Get intermediate certificate path from config
            ca_section = find_section(self.config, 'ca')
            if not ca_section:
                raise Exception('CA section not found in config.')
            
            default_ca_name = clean_config_value(self.config[ca_section].get('default_ca', ''))
            openssl_logger.info(f"Default CA name from config: {default_ca_name}")
            
            default_ca_section = find_section(self.config, default_ca_name)
            if not default_ca_section:
                raise Exception(f'Default CA section "{default_ca_name}" not found in config.')
            
            # Get intermediate certificate path
            intermediate_cert_raw = clean_config_value(self.config[default_ca_section].get('certificate', ''))
            if not intermediate_cert_raw:
                raise Exception('Intermediate certificate path not found in CA config.')
            
            openssl_logger.info(f"Intermediate certificate (raw path): {intermediate_cert_raw}")
            
            # Resolve intermediate certificate path
            config_dir = os.path.dirname(os.path.abspath(self.configPathEdit.text().strip()))
            dir_raw = clean_config_value(self.config[default_ca_section].get('dir', '.'))
            
            if not os.path.isabs(dir_raw):
                base_dir = os.path.normpath(os.path.join(config_dir, dir_raw))
            else:
                base_dir = os.path.normpath(dir_raw)
            
            variables = {
                'dir': base_dir,
                'config_dir': config_dir
            }
            
            openssl_logger.info(f"Base directory: {base_dir}")
            openssl_logger.info(f"Config directory: {config_dir}")
            
            intermediate_cert_path = resolve_path(intermediate_cert_raw, variables)
            if not os.path.isabs(intermediate_cert_path):
                intermediate_cert_path = os.path.join(base_dir, intermediate_cert_path)
            
            openssl_logger.info(f"Intermediate certificate (resolved): {intermediate_cert_path}")
            
            # Verify all certificate files exist
            if not os.path.exists(cert_path):
                raise Exception(f'Selected certificate not found: {cert_path}')
            if not os.path.exists(intermediate_cert_path):
                raise Exception(f'Intermediate certificate not found: {intermediate_cert_path}')
            if not os.path.exists(root_ca_path):
                raise Exception(f'Root CA certificate not found: {root_ca_path}')
            
            openssl_logger.info("All certificate files verified and exist")
            
            # Create keychain file path
            keychain_filename = f"keychain.{cert_name}.cert.pem"
            keychain_path = os.path.join(self.certs_dir, keychain_filename)
            
            openssl_logger.info(f"Target keychain file: {keychain_path}")
            
            # Read certificate contents and log file sizes
            with open(cert_path, 'r') as f:
                selected_cert_content = f.read().strip()
            openssl_logger.info(f"Selected certificate read: {len(selected_cert_content)} characters")
            
            with open(intermediate_cert_path, 'r') as f:
                intermediate_cert_content = f.read().strip()
            openssl_logger.info(f"Intermediate certificate read: {len(intermediate_cert_content)} characters")
            
            with open(root_ca_path, 'r') as f:
                root_ca_content = f.read().strip()
            openssl_logger.info(f"Root CA certificate read: {len(root_ca_content)} characters")
            
            # Create keychain content (selected cert + intermediate + root CA)
            keychain_content = selected_cert_content + '\n' + intermediate_cert_content + '\n' + root_ca_content + '\n'
            total_length = len(keychain_content)
            
            openssl_logger.info(f"Keychain content prepared: {total_length} total characters")
            openssl_logger.info("Keychain structure: Selected Certificate + Intermediate Certificate + Root CA Certificate")
            
            # Write keychain file
            openssl_logger.info(f"Writing keychain file to: {keychain_path}")
            with open(keychain_path, 'w') as f:
                f.write(keychain_content)
            
            # Verify the file was written
            if os.path.exists(keychain_path):
                file_size = os.path.getsize(keychain_path)
                openssl_logger.info(f"Keychain file written successfully: {file_size} bytes")
            else:
                raise Exception("Keychain file was not created successfully")
            
            openssl_logger.info("=" * 80)
            openssl_logger.info(f"Keychain creation completed successfully: {keychain_filename}")
            openssl_logger.info("=" * 80)
            openssl_logger.info("")  # Empty line for separation
            
            # Success message
            QtWidgets.QMessageBox.information(
                self, 'Keychain Created Successfully',
                f'Keychain file "{keychain_filename}" has been created successfully!\n\n'
                f'Location: {keychain_path}\n\n'
                f'Contents:\n'
                f'• Selected Certificate: {os.path.basename(cert_path)}\n'
                f'• Intermediate Certificate: {os.path.basename(intermediate_cert_path)}\n'
                f'• Root CA Certificate: {os.path.basename(root_ca_path)}\n\n'
                f'Operation logged to:\n{LOG_FILE}'
            )
            
            # Refresh certificate list to show new keychain file
            openssl_logger.info(f"Refreshing certificate list to show new keychain: {keychain_filename}")
            self.load_certificates_list()
            
        except Exception as e:
            openssl_logger.error("=" * 80)
            openssl_logger.error(f"Keychain creation failed for {cert_name}: {str(e)}")
            openssl_logger.error("=" * 80)
            openssl_logger.error("")  # Empty line for separation
            
            QtWidgets.QMessageBox.critical(
                self, 'Keychain Creation Failed',
                f'Failed to create keychain for certificate "{cert_file}":\n\n{str(e)}\n\n'
                f'Check log file for details:\n{LOG_FILE}'
            )
    def show_cert_details(self, item, column):
        cert_path = item.data(0, QtCore.Qt.UserRole)
        cert_type = item.data(1, QtCore.Qt.UserRole)

        if cert_type == "chain":
            # Handle certificate chain
            certificates = extract_certificates(cert_path)
            detail_text = f"Certificate Chain ({len(certificates)} certificates):\n\n"

            for i, cert_content in enumerate(certificates, 1):
                # Create temporary file for each certificate
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
                    temp_file.write(cert_content)
                    temp_path = temp_file.name

                try:
                    result = run_openssl_command(
                        ["openssl", "x509", "-in", temp_path, "-noout", "-text"],
                        description=f"Get details for certificate {i} in chain {os.path.basename(cert_path)}"
                    )

                    detail_text += f"=== Certificate {i} ===\n"
                    detail_text += result.stdout if result.returncode == 0 else result.stderr
                    detail_text += "\n\n"

                finally:
                    # Clean up temporary file
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
        else:
            # Handle single certificate
            result = run_openssl_command(
                ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
                description=f"Get details for certificate {os.path.basename(cert_path)}"
            )

            detail_text = result.stdout if result.returncode == 0 else result.stderr

        san_entries = get_certificate_san(cert_path)
        config = self.config
        base_sections = self.ca_sections if hasattr(self, 'ca_sections') else []

        matched_sections = []
        for sec in config.sections():
            if sec in base_sections:
                continue

            values_joined = " ".join(config[sec].values())
            matched = any(san in values_joined for san in san_entries)

            for k, v in config[sec].items():
                clean_v = clean_config_value(v)
                
                # Enhanced check using is_subsection function
                if is_subsection(clean_v, config):
                    # This value references a subsection
                    ref_sec_real = find_section(config, clean_v)
                    if ref_sec_real:
                        ref_vals = " ".join(config[ref_sec_real].values())
                        if any(san in ref_vals for san in san_entries):
                            matched = True
                elif clean_v.startswith("@"):
                    ref_sec = clean_v[1:]
                    ref_sec_real = find_section(config, ref_sec)
                    if ref_sec_real:
                        ref_vals = " ".join(config[ref_sec_real].values())
                        if any(san in ref_vals for san in san_entries):
                            matched = True

            if matched:
                matched_sections.append(sec)

        expanded_matched_sections = []
        visited = set()
        for ms in matched_sections:
            expanded_matched_sections += get_all_linked_sections(config, ms, visited)

        expanded_matched_sections = list(dict.fromkeys(expanded_matched_sections))

        config_text = format_sections(config, base_sections)
        config_text += "\n# Sections related to this certificate:\n\n"
        config_text += format_sections(config, expanded_matched_sections)

        self.certDetailsText.setText(detail_text)
        self.configDetailsText.setText(config_text)

def main():
    app = QtWidgets.QApplication([])
    gui = CAManager()
    gui.resize(1200, 700)
    gui.show()
    app.exec_()

if __name__ == '__main__':
    main()
