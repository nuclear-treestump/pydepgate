"""pydepgate.scanning.__init__

Internal scanner execution APIs."""

from pydepgate.scanning.api import (
    EvidenceWriteResult,
    ScanApiContractError,
    ScanTargetRef,
)
from pydepgate.scanning.cve_runner import (
    CveScanError,
    CveScanOutcome,
    CveScanRequest,
    execute_cve_scan,
)
from pydepgate.scanning.static_runner import (
    StaticDecodeOptions,
    StaticScanError,
    StaticScanOutcome,
    StaticScanRequest,
    execute_static_scan,
)

__all__ = [
    "EvidenceWriteResult",
    "ScanApiContractError",
    "ScanTargetRef",
    "CveScanError",
    "CveScanOutcome",
    "CveScanRequest",
    "execute_cve_scan",
    "StaticDecodeOptions",
    "StaticScanError",
    "StaticScanOutcome",
    "StaticScanRequest",
    "execute_static_scan",
]
