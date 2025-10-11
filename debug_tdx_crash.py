#!/usr/bin/env python3
"""
Debug script for TDX report generation crash.
"""

import logging
import faulthandler
import os
import signal
import sys

# Enable fault handler to get better crash information
faulthandler.enable()
faulthandler.register(signal.SIGUSR1)


def setup_debug_logging():
    """Configure detailed logging."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("/tmp/tdx_debug.log"),
        ],
    )


def test_minimal_tdx_generation():
    """Test with minimal parameters to isolate crash."""
    print("=== Minimal TDX Generation Test ===")

    try:
        import trustflow.attestation.generation as tdx_generation
        from trustflow.attestation.common import (
            AttestationGenerationParams,
            AttestationReportParams,
        )

        print("✓ TrustFlow modules imported successfully")

        # Test 1: Empty user data
        print("\nTest 1: Empty user data")
        params_empty = AttestationGenerationParams(
            tee_identity="tdx_instance",
            report_type="Passport",
            report_params=AttestationReportParams(hex_user_data=""),
        )
        print("Parameters created, attempting generation...")
        report = tdx_generation.generate_report(params_empty)
        print("✓ Empty user data test passed")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()


def test_memory_debug():
    """Test with memory debugging."""
    print("\n=== Memory Debug Test ===")

    try:
        import trustflow.attestation.generation as tdx_generation
        from trustflow.attestation.common import (
            AttestationGenerationParams,
            AttestationReportParams,
        )

        # Enable memory debugging
        import tracemalloc

        tracemalloc.start()

        print("Taking memory snapshot before generation...")
        snapshot1 = tracemalloc.take_snapshot()

        # Generate report
        params = AttestationGenerationParams(
            tee_identity="tdx_instance",
            report_type="Passport",
            report_params=AttestationReportParams(hex_user_data="deadbeef"),
        )

        report = tdx_generation.generate_report(params)

        print("Taking memory snapshot after generation...")
        snapshot2 = tracemalloc.take_snapshot()

        # Compare memory usage
        top_stats = snapshot2.compare_to(snapshot1, "lineno")
        print("[ Top 10 differences ]")
        for stat in top_stats[:10]:
            print(stat)

        tracemalloc.stop()

    except Exception as e:
        print(f"❌ Memory debug failed: {e}")


def check_tdx_quote_provider():
    """Check TDX quote provider configuration."""
    print("\n=== TDX Quote Provider Check ===")

    # Check for PCCS configuration
    pccs_configs = [
        "/etc/sgx_default_qcnl.conf",
        "/etc/sgx_qcnl.conf",
        "/opt/intel/sgx-pck-id-retrieval-tool/network_setting.conf",
    ]

    for config in pccs_configs:
        if os.path.exists(config):
            print(f"✓ Found PCCS config: {config}")
            with open(config, "r") as f:
                content = f.read()
                print(f"Content preview: {content[:200]}...")
        else:
            print(f"✗ Missing PCCS config: {config}")

    # Check for quote provider libraries
    quote_providers = [
        "/usr/lib/x86_64-linux-gnu/libtdx_attest.so",
        "/usr/lib64/libtdx_attest.so",
        "/opt/intel/sgx-dcap-pccs/lib/libtdx_attest.so",
    ]

    for provider in quote_providers:
        if os.path.exists(provider):
            print(f"✓ Found quote provider: {provider}")
        else:
            print(f"✗ Missing quote provider: {provider}")


def check_environment():
    """Check system environment for TDX."""
    print("\n=== Environment Check ===")

    import os
    import subprocess

    # Check environment variables
    tdx_env_vars = [
        "TDX_QGS_ADDR",
        "TDX_QGS_PORT",
        "PCCS_ADDR",
        "PCCS_PORT",
        "SGX_AESM_ADDR",
        "SGX_AESM_PORT",
    ]

    for var in tdx_env_vars:
        value = os.environ.get(var)
        if value:
            print(f"✓ {var}={value}")
        else:
            print(f"✗ {var} not set")

    # Check system services
    services = ["pccs", "qgs", "aesmd"]
    for service in services:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service], capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"✓ Service {service} is active")
            else:
                print(f"✗ Service {service} is not active")
        except Exception as e:
            print(f"✗ Could not check service {service}: {e}")


def main():
    """Run debug tests."""
    setup_debug_logging()

    print("🔧 TDX Crash Debug Script")
    print("=" * 50)

    # Check environment first
    check_environment()
    check_tdx_quote_provider()

    # Run minimal test
    test_minimal_tdx_generation()

    # Run memory debug test
    test_memory_debug()

    print("\n" + "=" * 50)
    print("📝 Check /tmp/tdx_debug.log for detailed logs")


if __name__ == "__main__":
    main()
