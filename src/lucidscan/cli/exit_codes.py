"""Exit codes for lucidscan CLI.

Exit codes follow Section 14 of the specification:
- 0: Success (no issues found or below threshold)
- 1: Issues found at or above severity threshold
- 2: Scanner error
- 3: Invalid usage (bad arguments, missing config)
- 4: Bootstrap failure (binary download failed)
"""

from __future__ import annotations

EXIT_SUCCESS = 0
EXIT_ISSUES_FOUND = 1
EXIT_SCANNER_ERROR = 2
EXIT_INVALID_USAGE = 3
EXIT_BOOTSTRAP_FAILURE = 4
