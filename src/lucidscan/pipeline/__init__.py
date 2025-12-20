"""Pipeline orchestration for lucidscan.

Manages the execution of scan pipeline stages:
1. Scanner execution (parallel by default)
2. Enricher execution (sequential, in configured order)
3. Result aggregation (metadata and summary)
"""

from lucidscan.pipeline.executor import PipelineConfig, PipelineExecutor
from lucidscan.pipeline.parallel import ParallelScannerExecutor, ScannerResult

__all__ = [
    "PipelineConfig",
    "PipelineExecutor",
    "ParallelScannerExecutor",
    "ScannerResult",
]
