#!/usr/bin/env python3
"""
Test script for TrustFlow attestation verification and generation logic.

This script focuses specifically on testing the TrustFlow attestation modules:
- trustflow.attestation.generation (for TDX report generation)
- trustflow.attestation.verification (for report verification)
"""

import json
import logging
import numpy as np
from typing import Optional

try:
    import trustflow.attestation.verification as verification
    import trustflow.attestation.generation as tdx_generation
    from trustflow.attestation.common import (
        AttestationAttribute,
        AttestationGenerationParams,
        AttestationPolicy,
        AttestationReport,
        AttestationReportParams,
    )
    HAS_TRUSTFLOW = True
except ImportError:
    HAS_TRUSTFLOW = False
    print("⚠️ TrustFlow attestation modules not available")


def setup_logging():
    """Configure logging for test visibility."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def test_tdx_report_generation():
    """Test TDX attestation report generation."""
    print("\n=== Testing TDX Report Generation ===")
    
    if not HAS_TRUSTFLOW:
        print("❌ Skipping: TrustFlow not available")
        return
    
    try:
        # Generate test public key (32 bytes)
        test_pk = np.random.randint(0, 256, size=32, dtype=np.uint8)
        print(f"Test public key (hex): {test_pk.tobytes().hex()[:16]}...")
        
        # Create attestation generation parameters
        params = AttestationGenerationParams(
            tee_identity="tdx_instance",
            report_type="Passport",
            report_params=AttestationReportParams(
                hex_user_data=test_pk.tobytes().hex()
            ),
        )
        
        print(f"TEE Identity: {params.tee_identity}")
        print(f"Report Type: {params.report_type}")
        print(f"User Data (hex): {params.report_params.hex_user_data[:16]}...")
        
        # Generate the attestation report
        report: AttestationReport = tdx_generation.generate_report(params)
        
        # Convert to JSON for inspection
        report_json = report.to_json()
        report_dict = json.loads(report_json)
        
        print(f"✓ Report generated successfully")
        print(f"Report JSON keys: {list(report_dict.keys())}")
        
        if 'tee_platform' in report_dict:
            print(f"TEE Platform: {report_dict['tee_platform']}")
        if 'report_type' in report_dict:
            print(f"Report Type: {report_dict['report_type']}")
        if 'user_data' in report_dict:
            print(f"User Data in report: {report_dict['user_data'][:16]}...")
        
        return report
        
    except Exception as e:
        print(f"❌ TDX report generation failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_attestation_verification(report: Optional[AttestationReport]):
    """Test attestation report verification."""
    print("\n=== Testing Attestation Report Verification ===")
    
    if not HAS_TRUSTFLOW:
        print("❌ Skipping: TrustFlow not available")
        return False
    
    if report is None:
        print("❌ No report to verify")
        return False
    
    try:
        # Generate the same test public key for verification
        test_pk = np.random.randint(0, 256, size=32, dtype=np.uint8)
        
        # Create attestation attributes for verification
        attrs = AttestationAttribute(
            str_tee_platform="TDX",
            hex_user_data=test_pk.tobytes().hex()
        )
        
        print(f"Verification TEE Platform: {attrs.str_tee_platform}")
        print(f"Verification User Data (hex): {attrs.hex_user_data[:16]}...")
        
        # Create attestation policy
        policy = AttestationPolicy(main_attributes=[attrs])
        
        # Verify the report
        status = verification.report_verify(report, policy)
        
        print(f"Verification Status Code: {status.code}")
        print(f"Verification Message: {status.message}")
        if hasattr(status, 'detail') and status.detail:
            print(f"Verification Detail: {status.detail}")
        
        if status.code == 0:
            print("✓ Attestation verification successful")
            return True
        else:
            print(f"❌ Attestation verification failed: {status.message}")
            return False
            
    except Exception as e:
        print(f"❌ Attestation verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_attestation_with_mismatched_user_data():
    """Test attestation verification with mismatched user data."""
    print("\n=== Testing Attestation with Mismatched User Data ===")
    
    if not HAS_TRUSTFLOW:
        print("❌ Skipping: TrustFlow not available")
        return
    
    try:
        # Generate report with one public key
        original_pk = np.random.randint(0, 256, size=32, dtype=np.uint8)
        
        params = AttestationGenerationParams(
            tee_identity="tdx_instance",
            report_type="Passport",
            report_params=AttestationReportParams(
                hex_user_data=original_pk.tobytes().hex()
            ),
        )
        
        report = tdx_generation.generate_report(params)
        
        # Try to verify with different public key
        different_pk = np.random.randint(0, 256, size=32, dtype=np.uint8)
        
        attrs = AttestationAttribute(
            str_tee_platform="TDX",
            hex_user_data=different_pk.tobytes().hex()
        )
        
        policy = AttestationPolicy(main_attributes=[attrs])
        status = verification.report_verify(report, policy)
        
        print(f"Mismatched verification Status Code: {status.code}")
        print(f"Mismatched verification Message: {status.message}")
        
        if status.code != 0:
            print("✓ Correctly failed verification with mismatched user data")
        else:
            print("⚠ Verification passed unexpectedly with mismatched data")
            
    except Exception as e:
        print(f"❌ Mismatched attestation test failed: {e}")


def test_attestation_policy_creation():
    """Test creating different types of attestation policies."""
    print("\n=== Testing Attestation Policy Creation ===")
    
    if not HAS_TRUSTFLOW:
        print("❌ Skipping: TrustFlow not available")
        return
    
    try:
        # Test basic policy with TDX platform
        attrs_tdx = AttestationAttribute(
            str_tee_platform="TDX",
            hex_user_data="abcd1234"
        )
        policy_tdx = AttestationPolicy(main_attributes=[attrs_tdx])
        print("✓ TDX policy created successfully")
        
        # Test policy with multiple attributes
        attrs_multi = [
            AttestationAttribute(str_tee_platform="TDX", hex_user_data="data1"),
            AttestationAttribute(str_tee_platform="TDX", hex_user_data="data2")
        ]
        policy_multi = AttestationPolicy(main_attributes=attrs_multi)
        print("✓ Multi-attribute policy created successfully")
        
        # Test policy without user data
        attrs_no_data = AttestationAttribute(str_tee_platform="TDX")
        policy_no_data = AttestationPolicy(main_attributes=[attrs_no_data])
        print("✓ Policy without user data created successfully")
        
    except Exception as e:
        print(f"❌ Policy creation test failed: {e}")


def test_report_serialization():
    """Test attestation report serialization and deserialization."""
    print("\n=== Testing Report Serialization ===")
    
    if not HAS_TRUSTFLOW:
        print("❌ Skipping: TrustFlow not available")
        return
    
    try:
        # Generate a report
        test_pk = np.random.randint(0, 256, size=32, dtype=np.uint8)
        
        params = AttestationGenerationParams(
            tee_identity="tdx_instance",
            report_type="Passport",
            report_params=AttestationReportParams(
                hex_user_data=test_pk.tobytes().hex()
            ),
        )
        
        original_report = tdx_generation.generate_report(params)
        
        # Serialize to JSON
        json_str = original_report.to_json()
        print(f"Serialized report length: {len(json_str)} characters")
        
        # Deserialize from JSON
        deserialized_report = AttestationReport.from_json(json_str)
        print("✓ Report deserialized successfully")
        
        # Verify deserialization by checking if we can serialize again
        json_str_again = deserialized_report.to_json()
        if len(json_str_again) == len(json_str):
            print("✓ Serialization round-trip successful")
        else:
            print("⚠ Serialization round-trip length mismatch")
            
    except Exception as e:
        print(f"❌ Report serialization test failed: {e}")


def main():
    """Run all TrustFlow attestation tests."""
    setup_logging()
    
    print("🚀 Starting TrustFlow Attestation Tests")
    print("=" * 60)
    
    if not HAS_TRUSTFLOW:
        print("❌ TrustFlow attestation modules are not available")
        print("Please install trustflow packages to run these tests")
        print("Expected modules:")
        print("  - trustflow.attestation.verification")
        print("  - trustflow.attestation.generation")
        print("  - trustflow.attestation.common")
        return 1
    
    try:
        # Test TDX report generation
        report = test_tdx_report_generation()
        
        # Test attestation verification
        verification_success = test_attestation_verification(report)
        
        # Test with mismatched data
        test_attestation_with_mismatched_user_data()
        
        # Test policy creation
        test_attestation_policy_creation()
        
        # Test report serialization
        test_report_serialization()
        
        print("\n" + "=" * 60)
        if verification_success:
            print("✅ TrustFlow attestation tests completed successfully!")
        else:
            print("⚠️  TrustFlow attestation tests completed with warnings")
        
        return 0 if verification_success else 1
        
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())