# Copyright 2025 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json

import numpy as np
import trustflow.attestation.verification as verification
from mplang.core.pfunc import PFunction
from mplang.kernels.base import kernel_def
from mplang.kernels.context import _DEFAULT_BINDINGS
from mplang.utils.crypto import blake2b
from numpy.typing import NDArray
from trustflow.attestation.common import (
    AttestationAttribute,
    AttestationGenerationParams,
    AttestationPolicy,
    AttestationReport,
    AttestationReportParams,
)


# Register TEE related kernels
def ensure_tee_kernels() -> None:
    _DEFAULT_BINDINGS["tee.attest"] = "tee.attest"
    _DEFAULT_BINDINGS["tee.quote_gen"] = "tee.quote_gen"


def _build_quote(pk: NDArray, report_json: str) -> NDArray:
    # Enhanced quote structure:
    # 1-byte header + 32-byte pk + platform info + report json bytes
    header = np.array([2], dtype=np.uint8)
    pk32 = np.asarray(pk, dtype=np.uint8).reshape(32)

    # Add platform identifier to the quote data
    report_obj = json.loads(report_json)
    platform = str(report_obj["str_tee_platform"])

    platform_info = f"platform={platform.upper()};"
    platform_info_bytes = np.frombuffer(platform_info.encode("utf-8"), dtype=np.uint8)
    report_bytes = np.frombuffer(report_json.encode("utf-8"), dtype=np.uint8)

    ret: np.ndarray = np.concatenate([
        header,
        pk32,
        platform_info_bytes,
        report_bytes,
    ]).astype(np.uint8)
    return ret


@kernel_def("tee.quote_gen")
def _tee_quote_gen(pfunc: PFunction, pk: object) -> NDArray[np.uint8]:
    from trustflow.attestation import generation

    pk = np.asarray(pk, dtype=np.uint8)
    if pk.size != 32:
        raise ValueError("pk must be 32 bytes")

    # Generate platform-specific attestation report binding the provided pk
    params = AttestationGenerationParams(
        tee_identity="tee_instance",
        report_type="Passport",
        report_params=AttestationReportParams(
            hex_user_data=blake2b(pk.tobytes()).hex()
        ),
    )
    report: AttestationReport = generation.generate_report(params)
    report_json = report.to_json()

    return _build_quote(pk, report_json)


@kernel_def("tee.attest")
def _tee_attest(pfunc: PFunction, quote: object) -> NDArray[np.uint8]:
    # Verify and extract pk from quote
    quote = np.asarray(quote, dtype=np.uint8)
    if quote.size < 33:
        raise ValueError(
            "quote must be at least 33 bytes "
            "(1 header + 32 pk + platform info + report)"
        )
    if quote[0] != 2:
        raise ValueError("invalid quote header")
    pk = quote[1:33].astype(np.uint8)

    # Parse platform info and report from the remaining data
    remaining_data = quote[33:].tobytes().decode("utf-8")

    # Extract platform info (format: "platform=XXX;")
    platform_end = remaining_data.find(";")
    if platform_end == -1:
        raise ValueError("invalid platform info format in quote")
    platform_info = remaining_data[: platform_end + 1]

    # Extract platform from platform_info
    if not platform_info.startswith("platform="):
        raise ValueError("invalid platform info prefix in quote")
    platform = platform_info[9:-1]  # Remove "platform=" and ";"
    # Verify the attestation report with platform-specific settings
    if platform.upper() not in ["TDX", "SGX", "CSV"]:
        raise ValueError(
            f"Unsupported tee platform '{platform}'. Supported platforms: "
            f"['TDX', 'SGX', 'CSV']"
        )

    report_json = remaining_data[platform_end + 1 :]
    report = AttestationReport.from_json(report_json)

    attrs = AttestationAttribute(
        str_tee_platform=platform.upper(),
        hex_user_data=blake2b(pk.tobytes()).hex(),
    )
    status = verification.report_verify(
        report,
        AttestationPolicy(main_attributes=[attrs]),
    )
    if status.code != 0:
        raise ValueError(
            f"Attestation verification failed: {status.message} "
            f", detail: {status.detail}"
        )

    return pk
