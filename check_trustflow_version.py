#!/usr/bin/env python3
"""
Check TrustFlow version and compatibility.
"""

import importlib
import sys

def check_trustflow_installation():
    """Check TrustFlow installation details."""
    print("=== TrustFlow Installation Check ===")
    
    modules = [
        'trustflow',
        'trustflow.attestation',
        'trustflow.attestation.verification',
        'trustflow.attestation.generation',
        'trustflow.attestation.common'
    ]
    
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
            version = getattr(module, '__version__', 'unknown')
            path = getattr(module, '__file__', 'unknown')
            print(f"✓ {module_name} version: {version}")
            print(f"  Path: {path}")
            
            # List module contents
            if hasattr(module, '__all__'):
                print(f"  Exports: {module.__all__}")
            
        except ImportError as e:
            print(f"✗ {module_name}: {e}")

def check_dependencies():
    """Check related dependencies."""
    print("\n=== Dependency Check ===")
    
    dependencies = [
        'cryptography',
        'protobuf',
        'grpc',
        'sgx',
        'pycryptodome'
    ]
    
    for dep in dependencies:
        try:
            module = importlib.import_module(dep)
            version = getattr(module, '__version__', 'unknown')
            print(f"✓ {dep}: {version}")
        except ImportError:
            print(f"✗ {dep}: not installed")

def check_binary_dependencies():
    """Check system binary dependencies."""
    print("\n=== Binary Dependency Check ===")
    
    import subprocess
    import os
    
    binaries = [
        'sgx_quote_ex',
        'tdx_attest',
        'pccs',
        'qgs'
    ]
    
    for binary in binaries:
        try:
            result = subprocess.run(['which', binary], capture_output=True, text=True)
            if result.returncode == 0:
                path = result.stdout.strip()
                print(f"✓ {binary}: {path}")
                
                # Check library dependencies
                ldd_result = subprocess.run(['ldd', path], capture_output=True, text=True)
                if ldd_result.returncode == 0:
                    lines = ldd_result.stdout.split('\n')
                    print(f"  Dependencies: {len(lines)} libraries")
            else:
                print(f"✗ {binary}: not found in PATH")
        except Exception as e:
            print(f"✗ Error checking {binary}: {e}")

if __name__ == "__main__":
    check_trustflow_installation()
    check_dependencies()
    check_binary_dependencies()