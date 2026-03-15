"""Parse raw V8 coverage data from coverage/.tmp/ directories.

When Vitest uses @vitest/coverage-v8, it may write raw V8 coverage JSON
files to ``coverage/.tmp/`` before merging them into a summary report.
If no summary report was generated, this module can extract basic coverage
statistics directly from the raw V8 JSON files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from lucidshark.core.logging import get_logger
from lucidshark.plugins.coverage.base import CoverageResult, FileCoverage

LOGGER = get_logger(__name__)


def parse_v8_raw_coverage(
    raw_dir: Path,
    project_root: Path,
    threshold: float,
    tool_name: str,
) -> CoverageResult:
    """Parse raw V8 coverage JSON files to extract basic coverage stats.

    V8 coverage files contain an array of script coverage entries, each with
    ``url``, ``scriptId``, and ``functions`` (which contain ``ranges`` with
    ``startOffset``/``endOffset``/``count``).

    This provides a rough approximation based on byte ranges rather than
    exact line-level coverage, but is useful as a fallback when no Istanbul
    summary report was generated.

    Args:
        raw_dir: Directory containing raw V8 JSON coverage files.
        project_root: Project root directory.
        threshold: Coverage percentage threshold.
        tool_name: Name of the calling coverage tool.

    Returns:
        CoverageResult with approximate coverage statistics.
    """
    json_files = list(raw_dir.glob("**/*.json"))
    if not json_files:
        return CoverageResult(threshold=threshold, tool=tool_name)

    files: Dict[str, FileCoverage] = {}
    total_bytes = 0
    covered_bytes = 0

    for json_file in json_files:
        try:
            data = json.loads(json_file.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue

        # V8 raw format: {"result": [{"scriptId": ..., "url": ..., "functions": [...]}]}
        entries = data if isinstance(data, list) else data.get("result", [])
        if not isinstance(entries, list):
            continue

        for entry in entries:
            url = entry.get("url", "")
            # Skip node internals and node_modules
            if not url or "node_modules" in url or url.startswith("node:"):
                continue

            # Convert file:// URL or absolute path to relative
            file_path_str = url
            if file_path_str.startswith("file://"):
                file_path_str = file_path_str[7:]

            try:
                rel_path = str(Path(file_path_str).relative_to(project_root))
            except (ValueError, OSError):
                continue

            # Skip non-source files
            if not any(
                rel_path.endswith(ext)
                for ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
            ):
                continue

            functions = entry.get("functions", [])
            file_total = 0
            file_covered = 0

            for func in functions:
                for rng in func.get("ranges", []):
                    start = rng.get("startOffset", 0)
                    end = rng.get("endOffset", 0)
                    count = rng.get("count", 0)
                    span = end - start
                    if span > 0:
                        file_total += span
                        if count > 0:
                            file_covered += span

            if file_total > 0 and rel_path not in files:
                files[rel_path] = FileCoverage(
                    file_path=project_root / rel_path,
                    total_lines=file_total,
                    covered_lines=file_covered,
                )
                total_bytes += file_total
                covered_bytes += file_covered

    if total_bytes == 0:
        return CoverageResult(threshold=threshold, tool=tool_name)

    percentage = (covered_bytes / total_bytes) * 100

    LOGGER.info(
        f"Parsed raw V8 coverage from {raw_dir}: ~{percentage:.1f}% "
        f"({covered_bytes}/{total_bytes} bytes across {len(files)} files)"
    )

    return CoverageResult(
        total_lines=total_bytes,
        covered_lines=covered_bytes,
        missing_lines=total_bytes - covered_bytes,
        excluded_lines=0,
        threshold=threshold,
        files=files,
        tool=tool_name,
    )
