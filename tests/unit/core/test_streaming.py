"""Unit tests for stream handler module."""

from __future__ import annotations

import asyncio
import io
from typing import List, Tuple

import pytest

from lucidshark.core.streaming import (
    CallbackStreamHandler,
    CLIStreamHandler,
    MCPStreamHandler,
    NullStreamHandler,
    StreamEvent,
    StreamType,
)


class TestStreamType:
    """Tests for StreamType enum."""

    def test_stdout_value(self) -> None:
        """Test STDOUT enum value."""
        assert StreamType.STDOUT.value == "stdout"

    def test_stderr_value(self) -> None:
        """Test STDERR enum value."""
        assert StreamType.STDERR.value == "stderr"

    def test_status_value(self) -> None:
        """Test STATUS enum value."""
        assert StreamType.STATUS.value == "status"

    def test_is_string_enum(self) -> None:
        """Test StreamType is a string enum."""
        assert isinstance(StreamType.STDOUT, str)
        assert StreamType.STDOUT == "stdout"


class TestStreamEvent:
    """Tests for StreamEvent dataclass."""

    def test_basic_event(self) -> None:
        """Test creating a basic stream event."""
        event = StreamEvent(
            tool_name="pytest",
            stream_type=StreamType.STDOUT,
            content="test output",
        )
        assert event.tool_name == "pytest"
        assert event.stream_type == StreamType.STDOUT
        assert event.content == "test output"
        assert event.line_number is None

    def test_event_with_line_number(self) -> None:
        """Test creating event with line number."""
        event = StreamEvent(
            tool_name="ruff",
            stream_type=StreamType.STDERR,
            content="error on line 42",
            line_number=42,
        )
        assert event.line_number == 42


class TestNullStreamHandler:
    """Tests for NullStreamHandler."""

    def test_emit_is_noop(self) -> None:
        """Test emit does nothing."""
        handler = NullStreamHandler()
        event = StreamEvent(
            tool_name="test",
            stream_type=StreamType.STDOUT,
            content="content",
        )
        # Should not raise
        handler.emit(event)

    def test_start_tool_is_noop(self) -> None:
        """Test start_tool does nothing."""
        handler = NullStreamHandler()
        # Should not raise
        handler.start_tool("test_tool")

    def test_end_tool_is_noop(self) -> None:
        """Test end_tool does nothing."""
        handler = NullStreamHandler()
        # Should not raise
        handler.end_tool("test_tool", success=True)
        handler.end_tool("test_tool", success=False)


class TestCLIStreamHandler:
    """Tests for CLIStreamHandler."""

    def test_emit_with_show_output_false(self) -> None:
        """Test emit does nothing when show_output is False."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=False)
        event = StreamEvent(
            tool_name="test",
            stream_type=StreamType.STDOUT,
            content="content",
        )
        handler.emit(event)
        assert output.getvalue() == ""

    def test_emit_status_event(self) -> None:
        """Test emit outputs status events."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=True)
        event = StreamEvent(
            tool_name="pytest",
            stream_type=StreamType.STATUS,
            content="Running tests...",
        )
        handler.emit(event)
        assert "[pytest] Running tests..." in output.getvalue()

    def test_emit_stdout_event(self) -> None:
        """Test emit outputs stdout events with prefix."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=True)
        event = StreamEvent(
            tool_name="ruff",
            stream_type=StreamType.STDOUT,
            content="checking files...",
        )
        handler.emit(event)
        output_str = output.getvalue()
        assert "ruff:" in output_str
        assert "checking files..." in output_str

    def test_start_tool_outputs_starting_message(self) -> None:
        """Test start_tool outputs starting message."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=True)
        handler.start_tool("mypy")
        assert "[mypy] Starting..." in output.getvalue()

    def test_end_tool_success_outputs_done(self) -> None:
        """Test end_tool with success outputs Done."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=True)
        handler.end_tool("pytest", success=True)
        assert "[pytest] Done" in output.getvalue()

    def test_end_tool_failure_outputs_failed(self) -> None:
        """Test end_tool with failure outputs Failed."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=True)
        handler.end_tool("pytest", success=False)
        assert "[pytest] Failed" in output.getvalue()

    def test_emit_stderr_event(self) -> None:
        """Test emit outputs stderr events with prefix."""
        output = io.StringIO()
        handler = CLIStreamHandler(output=output, show_output=True)
        event = StreamEvent(
            tool_name="mypy",
            stream_type=StreamType.STDERR,
            content="error found",
        )
        handler.emit(event)
        output_str = output.getvalue()
        assert "mypy:" in output_str
        assert "error found" in output_str


class TestCallbackStreamHandler:
    """Tests for CallbackStreamHandler."""

    def test_emit_calls_on_event_callback(self) -> None:
        """Test emit invokes on_event callback."""
        events: List[StreamEvent] = []

        def on_event(event: StreamEvent) -> None:
            events.append(event)

        handler = CallbackStreamHandler(on_event=on_event)
        event = StreamEvent(
            tool_name="test",
            stream_type=StreamType.STDOUT,
            content="content",
        )
        handler.emit(event)

        assert len(events) == 1
        assert events[0] == event

    def test_emit_without_callback_is_noop(self) -> None:
        """Test emit does nothing without callback."""
        handler = CallbackStreamHandler()
        event = StreamEvent(
            tool_name="test",
            stream_type=StreamType.STDOUT,
            content="content",
        )
        # Should not raise
        handler.emit(event)

    def test_start_tool_calls_on_start_callback(self) -> None:
        """Test start_tool invokes on_start callback."""
        started_tools: List[str] = []

        def on_start(tool_name: str) -> None:
            started_tools.append(tool_name)

        handler = CallbackStreamHandler(on_start=on_start)
        handler.start_tool("pytest")

        assert started_tools == ["pytest"]

    def test_start_tool_also_emits_event(self) -> None:
        """Test start_tool also emits a status event."""
        events: List[StreamEvent] = []

        def on_event(event: StreamEvent) -> None:
            events.append(event)

        handler = CallbackStreamHandler(on_event=on_event)
        handler.start_tool("ruff")

        assert len(events) == 1
        assert events[0].tool_name == "ruff"
        assert events[0].stream_type == StreamType.STATUS
        assert events[0].content == "started"

    def test_end_tool_calls_on_end_callback(self) -> None:
        """Test end_tool invokes on_end callback."""
        ended_tools: List[Tuple[str, bool]] = []

        def on_end(tool_name: str, success: bool) -> None:
            ended_tools.append((tool_name, success))

        handler = CallbackStreamHandler(on_end=on_end)
        handler.end_tool("pytest", success=True)
        handler.end_tool("mypy", success=False)

        assert ended_tools == [("pytest", True), ("mypy", False)]

    def test_end_tool_also_emits_event(self) -> None:
        """Test end_tool also emits a status event."""
        events: List[StreamEvent] = []

        def on_event(event: StreamEvent) -> None:
            events.append(event)

        handler = CallbackStreamHandler(on_event=on_event)
        handler.end_tool("ruff", success=True)
        handler.end_tool("mypy", success=False)

        assert len(events) == 2
        assert events[0].content == "completed"
        assert events[1].content == "failed"


class TestMCPStreamHandler:
    """Tests for MCPStreamHandler."""

    @pytest.mark.asyncio
    async def test_emit_schedules_async_callback(self) -> None:
        """Test emit schedules async callback."""
        events: List[StreamEvent] = []

        async def on_event(event: StreamEvent) -> None:
            events.append(event)

        loop = asyncio.get_running_loop()
        handler = MCPStreamHandler(on_event=on_event, loop=loop)

        event = StreamEvent(
            tool_name="test",
            stream_type=StreamType.STDOUT,
            content="content",
        )
        handler.emit(event)

        # Allow time for callback to execute
        await asyncio.sleep(0.01)

        assert len(events) == 1
        assert events[0] == event

    @pytest.mark.asyncio
    async def test_start_tool_emits_started_event(self) -> None:
        """Test start_tool emits started status event."""
        events: List[StreamEvent] = []

        async def on_event(event: StreamEvent) -> None:
            events.append(event)

        loop = asyncio.get_running_loop()
        handler = MCPStreamHandler(on_event=on_event, loop=loop)

        handler.start_tool("pytest")

        await asyncio.sleep(0.01)

        assert len(events) == 1
        assert events[0].tool_name == "pytest"
        assert events[0].stream_type == StreamType.STATUS
        assert events[0].content == "started"

    @pytest.mark.asyncio
    async def test_end_tool_emits_completed_event(self) -> None:
        """Test end_tool emits completed status event on success."""
        events: List[StreamEvent] = []

        async def on_event(event: StreamEvent) -> None:
            events.append(event)

        loop = asyncio.get_running_loop()
        handler = MCPStreamHandler(on_event=on_event, loop=loop)

        handler.end_tool("pytest", success=True)

        await asyncio.sleep(0.01)

        assert len(events) == 1
        assert events[0].content == "completed"

    @pytest.mark.asyncio
    async def test_end_tool_emits_failed_event(self) -> None:
        """Test end_tool emits failed status event on failure."""
        events: List[StreamEvent] = []

        async def on_event(event: StreamEvent) -> None:
            events.append(event)

        loop = asyncio.get_running_loop()
        handler = MCPStreamHandler(on_event=on_event, loop=loop)

        handler.end_tool("pytest", success=False)

        await asyncio.sleep(0.01)

        assert len(events) == 1
        assert events[0].content == "failed"
