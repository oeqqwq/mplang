#!/usr/bin/env python3
"""
TrustFlow attestation report generation script.

This script generates TDX attestation reports that can be used for verification
in different environments. It focuses specifically on the report generation
functionality from the TrustFlow attestation modules.
"""

import argparse
import json
import logging
import os
import sys
import numpy as np
from typing import Optional

try:
    import trustflow.attestation.generation as tdx_generation
    from trustflow.attestation.common import (
        AttestationGenerationParams,
        AttestationReportParams,
        AttestationReport,
    )
    HAS_TRUSTFLOW = True
except ImportError:
    HAS_TRUSTFLOW = False


def setup_logging(verbose: bool = False):
    """Configure logging for the script."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def generate_attestation_report(
    user_data: Optional[str] = None,
    tee_identity: str = "tdx_instance", 
    report_type: str = "Passport"
):
    """
    Generate a TDX attestation report.
    
    Args:
        user_data: Optional hex string for user data (32 bytes)
        tee_identity: TEE identity string
        report_type: Type of report to generate
        
    Returns:
        AttestationReport object or None if generation failed
    """
    if not HAS_TRUSTFLOW:
        logging.error("TrustFlow attestation modules are not available")
        return None
    
    try:
        # Generate or use provided user data
        if user_data:
            # Validate user data is hex string
            if len(user_data) != 64:  # 32 bytes = 64 hex chars
                logging.warning(f"User data should be 64 hex characters (32 bytes), got {len(user_data)}")
            test_pk_hex = user_data
        else:
            # Generate random 32-byte public key
            test_pk = np.random.randint(0, 256, size=32, dtype=np.uint8)
            test_pk_hex = test_pk.tobytes().hex()
            logging.info(f"Generated random user data: {test_pk_hex[:16]}...")
        
        # Create attestation generation parameters
        params = AttestationGenerationParams(
            tee_identity=tee_identity,
            report_type=report_type,
            report_params=AttestationReportParams(
                hex_user_data=test_pk_hex
            ),
        )
        
        logging.info(f"Generating attestation report with TEE identity: {tee_identity}")
        logging.info(f"Report type: {report_type}")
        logging.info(f"User data (first 16 chars): {test_pk_hex[:16]}...")
        
        # Generate the attestation report
        report = tdx_generation.generate_report(params)
        
        logging.info("Attestation report generated successfully")
        return report
        
    except Exception as e:
        logging.error(f"Attestation report generation failed: {e}")
        return None


def save_report_to_file(report, output_file: str) -> bool:
    """Save attestation report to a JSON file."""
    try:
        report_json = report.to_json()
        with open(output_file, 'w') as f:
            json.dump(json.loads(report_json), f, indent=2)
        logging.info(f"Report saved to: {output_file}")
        return True
    except Exception as e:
        logging.error(f"Failed to save report to file: {e}")
        return False


def main():
    """Main function for the attestation report generation script."""
    parser = argparse.ArgumentParser(
        description="Generate TrustFlow TDX attestation reports"
    )
    parser.add_argument(
        "--user-data",
        type=str,
        help="Hex string user data (32 bytes, 64 hex characters)"
    )
    parser.add_argument(
        "--tee-identity",
        type=str,
        default="tdx_instance",
        help="TEE identity string (default: tdx_instance)"
    )
    parser.add_argument(
        "--report-type",
        type=str,
        default="Passport",
        help="Type of report to generate (default: Passport)"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output file path for the generated report (JSON format)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    if not HAS_TRUSTFLOW:
        logging.error("TrustFlow attestation modules are not available")
        logging.error("Please install trustflow packages:")
        logging.error("  - trustflow.attestation.generation")
        logging.error("  - trustflow.attestation.common")
        return 1
    
    logging.info("Starting TrustFlow attestation report generation")
    
    # Generate the attestation report
    report = generate_attestation_report(
        user_data=args.user_data,
        tee_identity=args.tee_identity,
        report_type=args.report_type
    )
    
    if report is None:
        logging.error("Failed to generate attestation report")
        return 1
    
    # Convert to JSON for output
    report_json = report.to_json()
    report_dict = json.loads(report_json)
    
    # Output the report
    if args.output:
        # Save to file
        if save_report_to_file(report, args.output):
            print(f"Report generated and saved to: {args.output}")
            print(f"User data in report: {report_dict.get('user_data', 'N/A')[:16]}...")
        else:
            logging.error("Failed to save report to file")
            return 1
    else:
        # Print to stdout
        print(json.dumps(report_dict, indent=2))
    
    logging.info("Attestation report generation completed successfully")
    return 0


if __name__ == "__main__":
    exit(main())