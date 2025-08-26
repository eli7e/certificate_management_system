#!/usr/bin/env python3
"""
Certificate Signing Request (CSR) Generator
A Streamlit web application for generating CSRs and private keys using OpenSSL.

Author: AI Assistant
Date: August 2025
"""

import streamlit as st
import subprocess
import os
import shutil
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Tuple, Optional
import re
import traceback
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
OPENSSL_CONFIG_FILE = "openssl.cfg"
DESTINATION_DIR = r"C:\scripts\certs"
TEMP_DIR = "temp_certs"

class CSRGenerator:
    """Main class for handling CSR generation and related operations."""
    
    def __init__(self):
        """Initialize the CSR Generator."""
        self.ensure_directories()
        
    def ensure_directories(self):
        """Ensure required directories exist."""
        try:
            # Create destination directory if it doesn't exist
            Path(DESTINATION_DIR).mkdir(parents=True, exist_ok=True)
            
            # Create temporary directory if it doesn't exist
            Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Directories ensured: {DESTINATION_DIR}, {TEMP_DIR}")
        except Exception as e:
            logger.error(f"Error creating directories: {str(e)}")
            raise
    
    def validate_certificate_name(self, cert_name: str) -> bool:
        """
        Validate certificate name to prevent security issues.
        
        Args:
            cert_name: Certificate name to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Allow only alphanumeric characters, hyphens, underscores, and dots
        pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(pattern, cert_name)) and len(cert_name) > 0
    
    def validate_email(self, email: str) -> bool:
        """
        Validate email address format.
        
        Args:
            email: Email address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def check_openssl_availability(self) -> bool:
        """
        Check if OpenSSL is available in the system.
        
        Returns:
            bool: True if OpenSSL is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["openssl", "version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def check_config_file(self) -> bool:
        """
        Check if OpenSSL configuration file exists.
        
        Returns:
            bool: True if config file exists, False otherwise
        """
        return Path(OPENSSL_CONFIG_FILE).exists()
    
    def generate_csr_and_key(self, certificate_name: str, use_password: bool = False) -> Tuple[bool, str, str, str]:
        """
        Generate CSR and private key using OpenSSL.
        
        Args:
            certificate_name: Name for the certificate files
            use_password: Whether to password-protect the private key
            
        Returns:
            Tuple containing:
            - bool: Success status
            - str: Path to CSR file
            - str: Path to key file
            - str: Error message if any
        """
        try:
            # File paths
            csr_file = f"{TEMP_DIR}/{certificate_name}.csr"
            key_file = f"{TEMP_DIR}/{certificate_name}.key"
            
            # Predefined password for key protection
            key_password = "B4mb00$h0tOfthe$outh!"
            
            # OpenSSL command to generate CSR and private key
            if use_password:
                # Generate password-protected private key
                cmd = [
                    "openssl", "req", "-new", "-newkey", "rsa:2048",
                    "-keyout", key_file,
                    "-out", csr_file,
                    "-config", OPENSSL_CONFIG_FILE,
                    "-batch",  # Don't prompt for input
                    "-passout", f"pass:{key_password}"
                ]
            else:
                # Generate unprotected private key (original behavior)
                cmd = [
                    "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key_file,
                    "-out", csr_file,
                    "-config", OPENSSL_CONFIG_FILE,
                    "-batch"  # Don't prompt for input
                ]
            
            logger.info(f"Executing OpenSSL command: {' '.join(cmd[:-2])}***")  # Hide password in logs
            
            # Execute the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.getcwd()
            )
            
            if result.returncode != 0:
                error_msg = f"OpenSSL command failed with return code {result.returncode}\n"
                error_msg += f"STDOUT: {result.stdout}\n"
                error_msg += f"STDERR: {result.stderr}"
                logger.error(error_msg)
                return False, "", "", error_msg
            
            # Check if files were created
            if not (Path(csr_file).exists() and Path(key_file).exists()):
                error_msg = "CSR or key file was not created successfully"
                logger.error(error_msg)
                return False, "", "", error_msg
            
            protection_status = "password-protected" if use_password else "unprotected"
            logger.info(f"Successfully generated CSR: {csr_file} and {protection_status} key: {key_file}")
            return True, csr_file, key_file, ""
            
        except subprocess.TimeoutExpired:
            error_msg = "OpenSSL command timed out"
            logger.error(error_msg)
            return False, "", "", error_msg
        except Exception as e:
            error_msg = f"Unexpected error during CSR generation: {str(e)}"
            logger.error(error_msg)
            return False, "", "", error_msg
    
    def verify_csr(self, csr_file: str) -> Tuple[bool, str]:
        """
        Verify the generated CSR using OpenSSL.
        
        Args:
            csr_file: Path to the CSR file
            
        Returns:
            Tuple containing:
            - bool: Success status
            - str: Verification output or error message
        """
        try:
            cmd = ["openssl", "req", "-in", csr_file, "-noout", "-text"]
            
            logger.info(f"Verifying CSR with command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                error_msg = f"CSR verification failed: {result.stderr}"
                logger.error(error_msg)
                return False, error_msg
            
            logger.info("CSR verification successful")
            return True, result.stdout
            
        except subprocess.TimeoutExpired:
            error_msg = "CSR verification command timed out"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during CSR verification: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def generate_pfx(self, certificate_name: str, crt_content: bytes, use_password: bool = False) -> Tuple[bool, str, str, str]:
        """
        Generate PFX file from uploaded certificate and existing private key.
        
        Args:
            certificate_name: Name for the certificate files
            crt_content: Content of the uploaded certificate file
            use_password: Whether the private key is password protected
            
        Returns:
            Tuple containing:
            - bool: Success status
            - str: Path to PFX file
            - str: Verification output
            - str: Error message if any
        """
        try:
            # File paths
            key_file = f"{DESTINATION_DIR}\\{certificate_name}.key"
            crt_file = f"{TEMP_DIR}/{certificate_name}.crt"
            pfx_file = f"{TEMP_DIR}/{certificate_name}.pfx"
            
            # Check if corresponding key file exists
            if not Path(key_file).exists():
                return False, "", "", f"Private key file not found: {key_file}"
            
            # Save uploaded certificate to temporary file
            with open(crt_file, 'wb') as f:
                f.write(crt_content)
            
            # Predefined password for PFX export
            pfx_password = "B4mb00$h0tOfthe$outh!"
            key_password = "B4mb00$h0tOfthe$outh!"
            
            # OpenSSL command to generate PFX
            if use_password:
                # Private key is password-protected
                cmd = [
                    "openssl", "pkcs12", "-export",
                    "-out", pfx_file,
                    "-inkey", key_file,
                    "-in", crt_file,
                    "-passin", f"pass:{key_password}",
                    "-passout", f"pass:{pfx_password}"
                ]
            else:
                # Private key is not password-protected
                cmd = [
                    "openssl", "pkcs12", "-export",
                    "-out", pfx_file,
                    "-inkey", key_file,
                    "-in", crt_file,
                    "-passout", f"pass:{pfx_password}"
                ]
            
            logger.info(f"Executing OpenSSL PFX command: {' '.join(cmd[:-2])}***")  # Hide password in logs
            
            # Execute the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.getcwd()
            )
            
            if result.returncode != 0:
                error_msg = f"OpenSSL PFX command failed with return code {result.returncode}\n"
                error_msg += f"STDOUT: {result.stdout}\n"
                error_msg += f"STDERR: {result.stderr}"
                logger.error(error_msg)
                return False, "", "", error_msg
            
            # Check if PFX file was created
            if not Path(pfx_file).exists():
                error_msg = "PFX file was not created successfully"
                logger.error(error_msg)
                return False, "", "", error_msg
            
            # Verify the PFX file
            verify_success, verification_output = self.verify_pfx(pfx_file)
            if not verify_success:
                error_msg = f"PFX verification failed: {verification_output}"
                logger.error(error_msg)
                return False, "", "", error_msg
            
            logger.info(f"Successfully generated PFX: {pfx_file}")
            return True, pfx_file, verification_output, ""
            
        except subprocess.TimeoutExpired:
            error_msg = "OpenSSL PFX command timed out"
            logger.error(error_msg)
            return False, "", "", error_msg
        except Exception as e:
            error_msg = f"Unexpected error during PFX generation: {str(e)}"
            logger.error(error_msg)
            return False, "", "", error_msg
    
    def verify_pfx(self, pfx_file: str) -> Tuple[bool, str]:
        """
        Verify the generated PFX file using OpenSSL.
        
        Args:
            pfx_file: Path to the PFX file
            
        Returns:
            Tuple containing:
            - bool: Success status
            - str: Verification output or error message
        """
        try:
            pfx_password = "B4mb00$h0tOfthe$outh!"
            cmd = [
                "openssl", "pkcs12", "-in", pfx_file, "-info", "-noout",
                "-passin", f"pass:{pfx_password}"
            ]
            
            logger.info(f"Verifying PFX with command: {' '.join(cmd[:-2])}***")  # Hide password in logs
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                error_msg = f"PFX verification failed: {result.stderr}"
                logger.error(error_msg)
                return False, error_msg
            
            logger.info("PFX verification successful")
            return True, result.stdout
            
        except subprocess.TimeoutExpired:
            error_msg = "PFX verification command timed out"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during PFX verification: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def copy_files_to_destination(self, csr_file: str, key_file: str, certificate_name: str) -> Tuple[bool, str, str, str]:
        """
        Copy CSR and key files to the destination directory.
        
        Args:
            csr_file: Source CSR file path
            key_file: Source key file path
            certificate_name: Certificate name for destination files
            
        Returns:
            Tuple containing:
            - bool: Success status
            - str: Destination CSR file path
            - str: Destination key file path
            - str: Error message if any
        """
        try:
            dest_csr = f"{DESTINATION_DIR}\\{certificate_name}.csr"
            dest_key = f"{DESTINATION_DIR}\\{certificate_name}.key"
            
            # Copy files
            shutil.copy2(csr_file, dest_csr)
            shutil.copy2(key_file, dest_key)
            
            # Verify files were copied
            if not (Path(dest_csr).exists() and Path(dest_key).exists()):
                error_msg = "Files were not copied successfully to destination"
                logger.error(error_msg)
                return False, "", "", error_msg
            
            logger.info(f"Files copied successfully to {DESTINATION_DIR}")
            return True, dest_csr, dest_key, ""
            
        except Exception as e:
            error_msg = f"Error copying files to destination: {str(e)}"
            logger.error(error_msg)
            return False, "", "", error_msg
    
    def send_email(self, user_email: str, certificate_name: str, csr_location: str = "", verification_result: str = "", password_protected: bool = False, pfx_location: str = "", pfx_verification: str = "", email_type: str = "csr") -> Tuple[bool, str]:
        """
        Send email with CSR or PFX details to the user.
        
        Args:
            user_email: Recipient email address
            certificate_name: Name of the certificate
            csr_location: Location of the CSR file
            verification_result: OpenSSL verification output
            password_protected: Whether the private key is password protected
            pfx_location: Location of the PFX file
            pfx_verification: PFX verification output
            email_type: Type of email ("csr" or "pfx")
            
        Returns:
            Tuple containing:
            - bool: Success status
            - str: Error message if any
        """
        try:
            # Email configuration (you may need to customize these settings)
            smtp_server = st.secrets.get("smtp_server", "localhost")
            smtp_port = st.secrets.get("smtp_port", 587)
            sender_email = st.secrets.get("sender_email", "noreply@company.com")
            sender_password = st.secrets.get("sender_password", "")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = user_email
            
            if email_type == "pfx":
                msg['Subject'] = f"PFX Certificate Package Generated: {certificate_name}"
                
                # Email body for PFX
                body = f"""
Dear User,

Your PFX certificate package has been successfully generated and is ready for use.

Certificate Package Details:
- Certificate Name: {certificate_name}
- PFX File Location: {pfx_location}
- PFX Password: B4mb00$h0tOfthe$outh!

⚠️ IMPORTANT SECURITY NOTICE:
Your PFX file is password-protected with: B4mb00$h0tOfthe$outh!
Please change this password immediately for production use.

PFX Verification Result:
{pfx_verification}

Installation Instructions:
1. Double-click the PFX file to install in Windows Certificate Store
2. Enter the password when prompted: B4mb00$h0tOfthe$outh!
3. Choose "Local Machine" or "Current User" as appropriate
4. Select "Automatically select the certificate store"

The PFX file contains your complete certificate chain and private key in a single package suitable for:
- IIS Web Server installations
- Application certificate deployment
- SSL/TLS certificate management

Best regards,
CSR Generator System
"""
            else:
                msg['Subject'] = f"Certificate Signing Request Generated: {certificate_name}"
                
                # Key protection information
                key_protection_info = ""
                if password_protected:
                    key_protection_info = """
⚠️ IMPORTANT SECURITY NOTICE:
Your private key is password-protected with the predefined password: B4mb00$h0tOfthe$outh!
Please change this password immediately after deployment for security purposes.

To remove the password protection from your key file, use:
openssl rsa -in {}.key -out {}_unprotected.key

To change the password, use:
openssl rsa -in {}.key -out {}_newpassword.key
""".format(certificate_name, certificate_name, certificate_name, certificate_name)
                else:
                    key_protection_info = """
⚠️ SECURITY NOTICE:
Your private key is NOT password-protected. Please secure this file appropriately.
"""
                
                # Email body for CSR
                body = f"""
Dear User,

Your Certificate Signing Request (CSR) has been successfully generated.

Certificate Details:
- Certificate Name: {certificate_name}
- CSR File Location: {csr_location}
- Key File Location: {csr_location.replace('.csr', '.key')}
- Key Protection: {'Password-Protected' if password_protected else 'Unprotected'}

{key_protection_info}

CSR Verification Result:
{verification_result}

Next Steps:
1. Submit the CSR file to your Certificate Authority (DigiCert, Let's Encrypt, etc.)
2. Once you receive the signed certificate, you can upload it back to generate a PFX package

Please securely store your private key file and use the CSR to obtain your certificate from your Certificate Authority.

Best regards,
CSR Generator System
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email (only if SMTP is configured)
            if sender_password:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(sender_email, sender_password)
                text = msg.as_string()
                server.sendmail(sender_email, user_email, text)
                server.quit()
                
                logger.info(f"Email sent successfully to {user_email}")
                return True, ""
            else:
                # Email not configured, just log the message
                logger.info(f"Email configuration not found. Would send to {user_email}:\n{body}")
                return True, "Email configuration not found - email content logged instead"
                
        except Exception as e:
            error_msg = f"Error sending email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def cleanup_temp_files(self, files_to_remove: list):
        """
        Clean up temporary files.
        
        Args:
            files_to_remove: List of file paths to remove
        """
        for file_path in files_to_remove:
            try:
                if Path(file_path).exists():
                    os.remove(file_path)
                    logger.info(f"Removed temporary file: {file_path}")
            except Exception as e:
                logger.error(f"Error removing temporary file {file_path}: {str(e)}")

def main():
    """Main Streamlit application."""
    
    # Page configuration
    st.set_page_config(
        page_title="CSR Generator",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<h1 class="main-header">🔐 Certificate Management System v2.0</h1>', unsafe_allow_html=True)
    
    # Create tabs for different functionalities
    tab1, tab2 = st.tabs(["🆕 Generate CSR", "📦 Create PFX Package"])
    
    # Initialize CSR Generator
    try:
        csr_gen = CSRGenerator()
    except Exception as e:
        st.error(f"Failed to initialize CSR Generator: {str(e)}")
        return
    
    # Sidebar with system checks
    with st.sidebar:
        st.header("System Status")
        
        # Check OpenSSL availability
        if csr_gen.check_openssl_availability():
            st.success("✅ OpenSSL is available")
        else:
            st.error("❌ OpenSSL is not available")
            st.stop()
        
        # Check config file
        if csr_gen.check_config_file():
            st.success("✅ OpenSSL config file found")
        else:
            st.error("❌ OpenSSL config file not found")
            st.stop()
        
        # Check destination directory
        if Path(DESTINATION_DIR).exists():
            st.success(f"✅ Destination directory: {DESTINATION_DIR}")
        else:
            st.warning(f"⚠️ Destination directory will be created: {DESTINATION_DIR}")
        
        st.markdown("---")
        st.markdown("### 📋 Certificate Manager")
        
        # List existing certificates
        cert_files = list(Path(DESTINATION_DIR).glob("*.key"))
        if cert_files:
            # Certificate selector dropdown
            cert_names = [cert_file.stem for cert_file in cert_files]
            selected_cert = st.selectbox(
                "🔍 Select Certificate",
                ["-- Select a certificate --"] + cert_names,
                help="Choose a certificate to view details and manage",
                key="sidebar_cert_select"
            )
            
            if selected_cert and selected_cert != "-- Select a certificate --":
                cert_path = Path(DESTINATION_DIR)
                cert_name = selected_cert
                
                # Certificate files
                key_file = cert_path / f"{cert_name}.key"
                csr_file = cert_path / f"{cert_name}.csr"
                crt_file = cert_path / f"{cert_name}.crt"
                pfx_file = cert_path / f"{cert_name}.pfx"
                
                st.markdown(f"**📋 {cert_name}**")
                
                # File availability with enhanced info
                components = []
                if key_file.exists():
                    # Check if key is encrypted
                    try:
                        with open(key_file, 'r') as f:
                            if "ENCRYPTED" in f.read():
                                components.append("🔐 KEY (Protected)")
                            else:
                                components.append("🔑 KEY")
                    except:
                        components.append("🔑 KEY")
                else:
                    components.append("❌ KEY Missing")
                
                if csr_file.exists():
                    components.append("📄 CSR")
                else:
                    components.append("❌ CSR Missing")
                
                if crt_file.exists():
                    components.append("📜 CRT")
                else:
                    components.append("❌ CRT Missing")
                
                if pfx_file.exists():
                    components.append("📦 PFX")
                else:
                    components.append("❌ PFX Missing")
                
                for component in components:
                    if "❌" in component:
                        st.markdown(f"  {component}")
                    elif "🔐" in component:
                        st.markdown(f"  {component}")
                    else:
                        st.markdown(f"  ✅ {component}")
                
                # Quick actions for selected certificate
                st.markdown("**Quick Actions:**")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if crt_file.exists() and not pfx_file.exists():
                        if st.button("📦 Make PFX", key=f"quick_pfx_{cert_name}", use_container_width=True):
                            st.info("💡 Switch to 'Create PFX Package' tab")
                    
                    if csr_file.exists():
                        if st.button("🔍 Verify CSR", key=f"quick_verify_{cert_name}", use_container_width=True):
                            try:
                                import subprocess
                                cmd = ["openssl", "req", "-in", str(csr_file), "-verify", "-noout"]
                                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                                if result.returncode == 0:
                                    st.success("✅ Valid CSR")
                                else:
                                    st.error("❌ Invalid CSR")
                            except Exception as e:
                                st.error(f"Error: {str(e)}")
                
                with col2:
                    if st.button("📋 Copy Path", key=f"copy_path_{cert_name}", use_container_width=True):
                        st.code(str(cert_path / cert_name))
                        st.info("📋 Path shown above")
                    
                    if pfx_file.exists():
                        if st.button("🔍 Test PFX", key=f"test_pfx_{cert_name}", use_container_width=True):
                            try:
                                import subprocess
                                cmd = ["openssl", "pkcs12", "-in", str(pfx_file), "-noout", "-passin", "pass:B4mb00$h0tOfthe$outh!"]
                                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                                if result.returncode == 0:
                                    st.success("✅ Valid PFX")
                                else:
                                    st.error("❌ Invalid PFX")
                            except Exception as e:
                                st.error(f"Error: {str(e)}")
                
                # Certificate info
                if key_file.exists():
                    file_size = key_file.stat().st_size
                    from datetime import datetime
                    mod_time = datetime.fromtimestamp(key_file.stat().st_mtime)
                    st.markdown(f"**Modified:** {mod_time.strftime('%Y-%m-%d %H:%M')}")
                    st.markdown(f"**Size:** {file_size} bytes")
                
                st.markdown("---")
                
                # Link to detailed viewer
                if st.button("🔍 Open Detailed Inspector", key=f"open_inspector_{cert_name}", use_container_width=True):
                    st.info("💡 Run: `streamlit run dropdown_demo.py`")
                    st.markdown("For comprehensive certificate analysis and management")
            
            # Summary stats
            st.markdown("---")
            st.markdown("### � Quick Stats")
            
            # Count different file types
            key_count = len(cert_files)
            csr_count = len(list(Path(DESTINATION_DIR).glob("*.csr")))
            crt_count = len(list(Path(DESTINATION_DIR).glob("*.crt")))
            pfx_count = len(list(Path(DESTINATION_DIR).glob("*.pfx")))
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("🔑 Keys", key_count)
                st.metric("📄 CSRs", csr_count)
            with col2:
                st.metric("📜 Certs", crt_count)
                st.metric("📦 PFX", pfx_count)
            
            # Completion percentage
            max_possible = key_count * 4
            actual_files = key_count + csr_count + crt_count + pfx_count
            completion = (actual_files / max_possible) * 100 if max_possible > 0 else 0
            
            st.progress(completion / 100)
            st.caption(f"Completion: {completion:.1f}%")
        else:
            st.info("No certificates found")
            st.markdown("Generate your first certificate using the **Generate CSR** tab")
        
        st.markdown("---")
        st.markdown("### 📚 Quick Links")
        
        if st.button("🔍 Certificate Inspector", use_container_width=True):
            st.info("Run: `streamlit run dropdown_demo.py`")
        
        if st.button("🎯 Demo Script", use_container_width=True):
            st.info("Run: `python demo.py`")
        
        st.markdown("### Instructions")
        st.markdown("""
        **Tab 1: Generate CSR**
        1. Enter your email address
        2. Provide a certificate name
        3. Choose password protection
        4. Click 'Generate CSR'
        5. Submit CSR to Certificate Authority
        
        **Tab 2: Create PFX**
        1. Upload signed certificate (.crt/.cer)
        2. Select matching certificate name
        3. Click 'Generate PFX Package'
        4. Install PFX in certificate store
        """)

    # Tab 1: CSR Generation
    with tab1:
        st.markdown("### Certificate Request Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            user_email = st.text_input(
                "📧 Email Address",
                placeholder="user@example.com",
                help="Enter your email address to receive the CSR details",
                key="csr_email"
            )
        
        with col2:
            certificate_name = st.text_input(
                "📜 Certificate Name",
                placeholder="my-certificate",
                help="Enter a name for your certificate (alphanumeric, hyphens, underscores, dots only)",
                key="csr_name"
            )
        
        # Password protection option
        password_protected = st.checkbox(
            "🔐 Password-protect private key",
            value=False,
            help="Enable this to protect the private key with the predefined password: B4mb00$h0tOfthe$outh!",
            key="csr_password"
        )
        
        if password_protected:
            st.info("🔒 Private key will be protected with predefined password: `B4mb00$h0tOfthe$outh!`")
            st.warning("⚠️ Remember to change this password in production environments!")
        else:
            st.info("🔓 Private key will be generated without password protection")
        
        # Validation warnings
        if user_email and not csr_gen.validate_email(user_email):
            st.warning("⚠️ Please enter a valid email address")
        
        if certificate_name and not csr_gen.validate_certificate_name(certificate_name):
            st.warning("⚠️ Certificate name can only contain letters, numbers, hyphens, underscores, and dots")
        
        # Generate button
        st.markdown("---")
        
        if st.button("🚀 Generate Certificate Signing Request", type="primary", use_container_width=True, key="generate_csr"):
            
            # Validation
            if not user_email or not certificate_name:
                st.error("❌ Please fill in all required fields")
            elif not csr_gen.validate_email(user_email):
                st.error("❌ Please enter a valid email address")
            elif not csr_gen.validate_certificate_name(certificate_name):
                st.error("❌ Invalid certificate name format")
            else:
                # Progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    # Step 1: Generate CSR and key
                    status_text.text("Generating CSR and private key...")
                    progress_bar.progress(20)
                    
                    success, csr_file, key_file, error_msg = csr_gen.generate_csr_and_key(certificate_name, password_protected)
                    
                    if not success:
                        st.error(f"❌ Failed to generate CSR: {error_msg}")
                    else:
                        # Step 2: Verify CSR
                        status_text.text("Verifying CSR...")
                        progress_bar.progress(40)
                        
                        verify_success, verification_result = csr_gen.verify_csr(csr_file)
                        
                        if not verify_success:
                            st.error(f"❌ Failed to verify CSR: {verification_result}")
                            # Clean up temporary files
                            csr_gen.cleanup_temp_files([csr_file, key_file])
                        else:
                            # Step 3: Copy files to destination
                            status_text.text("Copying files to destination...")
                            progress_bar.progress(60)
                            
                            copy_success, dest_csr, dest_key, copy_error = csr_gen.copy_files_to_destination(
                                csr_file, key_file, certificate_name
                            )
                            
                            if not copy_success:
                                st.error(f"❌ Failed to copy files: {copy_error}")
                                # Clean up temporary files
                                csr_gen.cleanup_temp_files([csr_file, key_file])
                            else:
                                # Step 4: Send email
                                status_text.text("Sending email notification...")
                                progress_bar.progress(80)
                                
                                email_success, email_error = csr_gen.send_email(
                                    user_email, certificate_name, dest_csr, verification_result, password_protected, email_type="csr"
                                )
                                
                                # Step 5: Clean up temporary files
                                status_text.text("Cleaning up...")
                                progress_bar.progress(90)
                                
                                csr_gen.cleanup_temp_files([csr_file, key_file])
                                
                                # Complete
                                progress_bar.progress(100)
                                status_text.text("Complete!")
                                
                                # Success message
                                st.markdown('<div class="success-box">', unsafe_allow_html=True)
                                st.success("✅ Certificate Signing Request generated successfully!")
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.markdown(f"**CSR File:** `{dest_csr}`")
                                with col2:
                                    st.markdown(f"**Key File:** `{dest_key}`")
                                
                                # Show password protection status
                                if password_protected:
                                    st.warning("🔐 **Private key is password-protected** with: `B4mb00$h0tOfthe$outh!`")
                                    st.info("💡 **Important**: Change this password in production environments!")
                                    
                                    # Show password removal command
                                    with st.expander("🛠️ Key Management Commands"):
                                        st.code(f"# Remove password protection:\nopenssl rsa -in {dest_key} -out {dest_key.replace('.key', '_unprotected.key')}", language="bash")
                                        st.code(f"# Change password:\nopenssl rsa -in {dest_key} -out {dest_key.replace('.key', '_newpassword.key')}", language="bash")
                                else:
                                    st.info("🔓 **Private key is unprotected** - ensure secure storage!")
                                
                                if email_success:
                                    st.info(f"📧 Email sent to: {user_email}")
                                else:
                                    st.warning(f"⚠️ Email notification failed: {email_error}")
                                
                                st.markdown('</div>', unsafe_allow_html=True)
                                
                                # Show verification details
                                with st.expander("🔍 CSR Verification Details"):
                                    st.code(verification_result, language="text")
                
                except Exception as e:
                    st.error(f"❌ Unexpected error: {str(e)}")
                    logger.error(f"Unexpected error in CSR generation: {traceback.format_exc()}")
                
                finally:
                    # Ensure progress bar shows completion
                    progress_bar.progress(100)
                    status_text.empty()

    # Tab 2: PFX Generation
    with tab2:
        st.markdown("### PFX Package Generation")
        st.info("📋 Upload your signed certificate to generate a complete PFX package for deployment.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            pfx_email = st.text_input(
                "📧 Email Address",
                placeholder="user@example.com",
                help="Enter your email address to receive the PFX details",
                key="pfx_email"
            )
        
        with col2:
            # Get list of available certificates with enhanced info
            cert_files = list(Path(DESTINATION_DIR).glob("*.key"))
            
            if cert_files:
                # Create enhanced certificate options
                cert_options = []
                cert_info = {}
                
                for cert_file in cert_files:
                    cert_name = cert_file.stem
                    csr_exists = (cert_file.parent / f"{cert_name}.csr").exists()
                    crt_exists = (cert_file.parent / f"{cert_name}.crt").exists()
                    pfx_exists = (cert_file.parent / f"{cert_name}.pfx").exists()
                    
                    # Build status string
                    status_parts = []
                    if csr_exists:
                        status_parts.append("CSR")
                    if crt_exists:
                        status_parts.append("CRT")
                    if pfx_exists:
                        status_parts.append("PFX")
                    
                    status = " + ".join(status_parts) if status_parts else "Key only"
                    
                    # Check if ready for PFX generation
                    ready_for_pfx = crt_exists and not pfx_exists
                    
                    if ready_for_pfx:
                        option_label = f"🟢 {cert_name} ({status}) - Ready for PFX"
                    elif pfx_exists:
                        option_label = f"🔵 {cert_name} ({status}) - PFX exists"
                    elif crt_exists:
                        option_label = f"🟡 {cert_name} ({status}) - Has certificate"
                    else:
                        option_label = f"🟠 {cert_name} ({status}) - Needs certificate"
                    
                    cert_options.append(option_label)
                    cert_info[option_label] = {
                        'name': cert_name,
                        'ready_for_pfx': ready_for_pfx,
                        'has_crt': crt_exists,
                        'has_pfx': pfx_exists
                    }
                
                selected_option = st.selectbox(
                    "📜 Select Certificate",
                    cert_options,
                    help="🟢 Ready for PFX | 🔵 PFX exists | 🟡 Has certificate | 🟠 Needs certificate",
                    key="pfx_cert_select"
                )
                
                if selected_option:
                    cert_data = cert_info[selected_option]
                    selected_cert = cert_data['name']
                    
                    # Show certificate status
                    if cert_data['ready_for_pfx']:
                        st.success("✅ Ready to generate PFX package")
                    elif cert_data['has_pfx']:
                        st.info("ℹ️ PFX package already exists")
                    elif cert_data['has_crt']:
                        st.warning("⚠️ Certificate available, but PFX exists")
                    else:
                        st.error("❌ Need signed certificate to generate PFX")
                else:
                    selected_cert = None
            else:
                st.error("❌ No certificates found. Please generate a CSR first.")
                selected_cert = None
        
        if selected_cert:
            # Check if key is password protected
            key_file_path = Path(DESTINATION_DIR) / f"{selected_cert}.key"
            
            # Try to detect if key is password protected by checking the header
            try:
                with open(key_file_path, 'r') as f:
                    first_line = f.readline().strip()
                    is_encrypted = "ENCRYPTED" in first_line
            except:
                is_encrypted = False
            
            if is_encrypted:
                st.info("🔐 Selected certificate has a password-protected private key")
            else:
                st.info("🔓 Selected certificate has an unprotected private key")
        
        # File upload
        uploaded_cert = st.file_uploader(
            "📤 Upload Signed Certificate",
            type=['crt', 'cer', 'pem'],
            help="Upload the certificate file you received from your Certificate Authority (DigiCert, Let's Encrypt, etc.)",
            key="cert_upload"
        )
        
        if uploaded_cert is not None:
            st.success(f"✅ Certificate uploaded: {uploaded_cert.name}")
            
            # Show certificate details
            with st.expander("📋 Certificate Information"):
                st.write(f"**Filename:** {uploaded_cert.name}")
                st.write(f"**Size:** {len(uploaded_cert.getvalue())} bytes")
                st.write(f"**Type:** {uploaded_cert.type}")
        
        # Validation warnings for PFX
        if pfx_email and not csr_gen.validate_email(pfx_email):
            st.warning("⚠️ Please enter a valid email address")
        
        # Generate PFX button
        st.markdown("---")
        
        if st.button("📦 Generate PFX Package", type="primary", use_container_width=True, key="generate_pfx"):
            
            # Validation
            if not pfx_email:
                st.error("❌ Please enter an email address")
            elif not selected_cert:
                st.error("❌ No certificate selected")
            elif uploaded_cert is None:
                st.error("❌ Please upload a signed certificate file")
            elif not csr_gen.validate_email(pfx_email):
                st.error("❌ Please enter a valid email address")
            else:
                # Progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    # Step 1: Generate PFX
                    status_text.text("Generating PFX package...")
                    progress_bar.progress(25)
                    
                    cert_content = uploaded_cert.getvalue()
                    success, pfx_file, pfx_verification, error_msg = csr_gen.generate_pfx(
                        selected_cert, cert_content, is_encrypted
                    )
                    
                    if not success:
                        st.error(f"❌ Failed to generate PFX: {error_msg}")
                    else:
                        # Step 2: Copy PFX to destination
                        status_text.text("Copying PFX to destination...")
                        progress_bar.progress(50)
                        
                        dest_pfx = f"{DESTINATION_DIR}\\{selected_cert}.pfx"
                        try:
                            shutil.copy2(pfx_file, dest_pfx)
                            logger.info(f"PFX file copied to: {dest_pfx}")
                        except Exception as e:
                            st.error(f"❌ Failed to copy PFX: {str(e)}")
                            csr_gen.cleanup_temp_files([pfx_file])
                        else:
                            # Step 3: Send email
                            status_text.text("Sending email notification...")
                            progress_bar.progress(75)
                            
                            email_success, email_error = csr_gen.send_email(
                                pfx_email, selected_cert, pfx_location=dest_pfx, 
                                pfx_verification=pfx_verification, email_type="pfx"
                            )
                            
                            # Step 4: Clean up temporary files
                            status_text.text("Cleaning up...")
                            progress_bar.progress(90)
                            
                            # Clean up temp files
                            temp_crt = f"{TEMP_DIR}/{selected_cert}.crt"
                            csr_gen.cleanup_temp_files([pfx_file, temp_crt])
                            
                            # Complete
                            progress_bar.progress(100)
                            status_text.text("Complete!")
                            
                            # Success message
                            st.markdown('<div class="success-box">', unsafe_allow_html=True)
                            st.success("✅ PFX package generated successfully!")
                            
                            st.markdown(f"**PFX File:** `{dest_pfx}`")
                            st.warning("🔐 **PFX is password-protected** with: `B4mb00$h0tOfthe$outh!`")
                            st.info("💡 **Important**: Change this password for production use!")
                            
                            if email_success:
                                st.info(f"📧 Email sent to: {pfx_email}")
                            else:
                                st.warning(f"⚠️ Email notification failed: {email_error}")
                            
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            # Show PFX verification details
                            with st.expander("🔍 PFX Verification Details"):
                                st.code(pfx_verification, language="text")
                            
                            # Installation instructions
                            with st.expander("📥 Installation Instructions"):
                                st.markdown("""
                                **Windows Certificate Store Installation:**
                                1. Double-click the PFX file
                                2. Choose "Local Machine" or "Current User"
                                3. Enter password: `B4mb00$h0tOfthe$outh!`
                                4. Select "Automatically select certificate store"
                                
                                **IIS Installation:**
                                1. Open IIS Manager
                                2. Go to Server Certificates
                                3. Click "Import"
                                4. Browse to PFX file
                                5. Enter password: `B4mb00$h0tOfthe$outh!`
                                
                                **Command Line Verification:**
                                ```bash
                                openssl pkcs12 -in certificate.pfx -info -noout
                                ```
                                """)
                
                except Exception as e:
                    st.error(f"❌ Unexpected error: {str(e)}")
                    logger.error(f"Unexpected error in PFX generation: {traceback.format_exc()}")
                
                finally:
                    # Ensure progress bar shows completion
                    progress_bar.progress(100)
                    status_text.empty()

if __name__ == "__main__":
    main()
