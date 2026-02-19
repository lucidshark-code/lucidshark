"""MCP (Model Context Protocol) integration for LucidShark.

This package provides MCP server functionality for AI agent integration,
enabling tools like Claude Code to invoke LucidShark checks.
"""

from __future__ import annotations

from lucidshark.mcp.server import LucidSharkMCPServer
from lucidshark.mcp.formatter import InstructionFormatter, FixInstruction
from lucidshark.mcp.tools import MCPToolExecutor
from lucidshark.mcp.watcher import LucidSharkFileWatcher

__all__ = [
    "LucidSharkMCPServer",
    "InstructionFormatter",
    "FixInstruction",
    "MCPToolExecutor",
    "LucidSharkFileWatcher",
]
