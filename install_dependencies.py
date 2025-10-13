#!/usr/bin/env python3
"""
🚀 CYBERPUNK AI PENTEST AGENT - Dependency Installer
Automatically installs required Python packages
"""

import subprocess
import sys
import os

def print_banner():
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║  🚀 CYBERPUNK AI PENTEST AGENT 2077 🚀               ║
    ║  Dependency Installation Script                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    print(f"[*] Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("[!] ERROR: Python 3.7 or higher is required!")
        return False
    
    print("[✓] Python version is compatible")
    return True

def install_package(package_name):
    """Install a Python package using pip"""
    print(f"\n[*] Installing {package_name}...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "--upgrade", package_name
        ])
        print(f"[✓] {package_name} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install {package_name}: {e}")
        return False

def check_package(package_name):
    """Check if a package is already installed"""
    try:
        __import__(package_name)
        print(f"[✓] {package_name} is already installed")
        return True
    except ImportError:
        return False

def main():
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # List of required packages
    required_packages = {
        'psutil': 'psutil',
        'requests': 'requests'
    }
    
    print("\n" + "="*60)
    print("CHECKING AND INSTALLING DEPENDENCIES")
    print("="*60)
    
    all_success = True
    
    for import_name, package_name in required_packages.items():
        if not check_package(import_name):
            if not install_package(package_name):
                all_success = False
    
    # Check tkinter (usually comes with Python)
    print("\n[*] Checking tkinter...")
    try:
        import tkinter
        print("[✓] tkinter is available")
    except ImportError:
        print("[!] WARNING: tkinter not found!")
        print("[!] On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("[!] On Fedora: sudo dnf install python3-tkinter")
        print("[!] On macOS: tkinter should be included with Python")
        all_success = False
    
    print("\n" + "="*60)
    
    if all_success:
        print("✅ ALL DEPENDENCIES INSTALLED SUCCESSFULLY!")
        print("\n🚀 You can now run: python3 AIlinuxV2.py")
    else:
        print("⚠️  SOME DEPENDENCIES FAILED TO INSTALL")
        print("Please install them manually and try again")
        sys.exit(1)
    
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
