
"""Compatibility wrapper for the safe AddAfterEOF watermarking method.

The original implementation used shell commands with shell=True.
This version contains no subprocess or shell execution and delegates
watermarking to AddAfterEOF.
"""

from __future__ import annotations

from typing import Final

from add_after_eof import AddAfterEOF


class UnsafeBashBridgeAppendEOF(AddAfterEOF):
    """Compatibility alias for the safe AddAfterEOF implementation."""

    name: Final[str] = "bash-bridge-eof"

    @staticmethod
    def get_usage() -> str:
        return (
            "Compatibility method that appends a watermark record after the PDF EOF."
        )


__all__ = ["UnsafeBashBridgeAppendEOF"]



