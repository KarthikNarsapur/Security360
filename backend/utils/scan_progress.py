"""
Scan Progress Tracker — WebSocket-based real-time progress.
Captures stdout (print statements) and forwards to WebSocket.
"""

import sys
import io
import asyncio
import threading
from datetime import datetime, timezone

# Store: { scan_id: { "percent", "message", "status", "websocket", "_loop" } }
_progress_store = {}
_lock = threading.Lock()


class ScanProgressCapture(io.TextIOBase):
    """
    Captures print() output during a scan and pushes each line to WebSocket.
    Also writes to the real stdout so terminal still shows output.
    """

    def __init__(self, scan_id: str, real_stdout):
        self.scan_id = scan_id
        self.real_stdout = real_stdout
        self._line_count = 0

    def write(self, text):
        # Always write to real terminal
        if self.real_stdout:
            self.real_stdout.write(text)

        # Skip empty/whitespace-only output
        stripped = text.strip()
        if not stripped:
            return len(text)

        self._line_count += 1

        # Auto-increment percent by 2 for each "Scanning..." category line
        with _lock:
            entry = _progress_store.get(self.scan_id)
            if entry and stripped.startswith("Scanning "):
                current = entry.get("percent", 0)
                new_percent = min(current + 2, 95)
                entry["percent"] = new_percent

        # Push to WebSocket as progress message
        with _lock:
            entry = _progress_store.get(self.scan_id)
            if entry:
                entry["message"] = stripped

        _send_ws(self.scan_id, stripped)
        return len(text)

    def flush(self):
        if self.real_stdout:
            self.real_stdout.flush()

    def isatty(self):
        return False


def _send_ws(scan_id: str, message: str):
    """Send a message via WebSocket if connected."""
    with _lock:
        entry = _progress_store.get(scan_id)
        if not entry:
            return
        ws = entry.get("websocket")
        loop = entry.get("_loop")
        percent = entry.get("percent", 0)

    if ws and loop:
        try:
            import json
            data = json.dumps({"percent": percent, "message": message, "status": "running"})
            asyncio.run_coroutine_threadsafe(ws.send_text(data), loop)
        except Exception:
            pass


def init_progress(scan_id: str):
    """Initialize a new scan progress entry."""
    with _lock:
        _progress_store[scan_id] = {
            "percent": 1,
            "message": "Starting scan...",
            "status": "running",
            "websocket": None,
            "_loop": None,
            "_line_count": 0,
        }


def set_websocket(scan_id: str, ws, loop):
    """Associate a WebSocket connection with a scan."""
    with _lock:
        if scan_id in _progress_store:
            _progress_store[scan_id]["websocket"] = ws
            _progress_store[scan_id]["_loop"] = loop


def update_progress(scan_id: str, percent: int, message: str):
    """Update progress percent. If message is empty, keep last message from print()."""
    with _lock:
        if scan_id not in _progress_store:
            return
        _progress_store[scan_id]["percent"] = min(percent, 100)
        if message:
            _progress_store[scan_id]["message"] = message

    # Send percent update (message already sent by print capture)
    if message:
        _send_ws(scan_id, message)


def complete_progress(scan_id: str):
    """Mark scan as complete and notify WebSocket."""
    with _lock:
        if scan_id not in _progress_store:
            return
        _progress_store[scan_id]["percent"] = 100
        _progress_store[scan_id]["message"] = "Scan complete!"
        _progress_store[scan_id]["status"] = "complete"
        ws = _progress_store[scan_id].get("websocket")
        loop = _progress_store[scan_id].get("_loop")

    if ws and loop:
        try:
            import json
            data = json.dumps({"percent": 100, "message": "Scan complete!", "status": "complete"})
            asyncio.run_coroutine_threadsafe(ws.send_text(data), loop)
        except Exception:
            pass


def fail_progress(scan_id: str, error: str):
    """Mark scan as failed and notify WebSocket."""
    with _lock:
        if scan_id not in _progress_store:
            return
        _progress_store[scan_id]["message"] = f"Error: {error}"
        _progress_store[scan_id]["status"] = "error"
        ws = _progress_store[scan_id].get("websocket")
        loop = _progress_store[scan_id].get("_loop")
        percent = _progress_store[scan_id].get("percent", 0)

    if ws and loop:
        try:
            import json
            data = json.dumps({"percent": percent, "message": f"Error: {error}", "status": "error"})
            asyncio.run_coroutine_threadsafe(ws.send_text(data), loop)
        except Exception:
            pass


def get_progress(scan_id: str) -> dict:
    """Get current progress (for polling fallback)."""
    with _lock:
        entry = _progress_store.get(scan_id)
        if not entry:
            return {"percent": 0, "message": "Unknown scan", "status": "unknown"}
        return {
            "percent": entry["percent"],
            "message": entry["message"],
            "status": entry["status"],
        }


def start_capture(scan_id: str):
    """
    Start capturing stdout for this scan.
    Returns the original stdout so it can be restored later.
    """
    real_stdout = sys.stdout
    capture = ScanProgressCapture(scan_id, real_stdout)
    sys.stdout = capture
    return real_stdout


def stop_capture(real_stdout):
    """Restore original stdout."""
    if real_stdout:
        sys.stdout = real_stdout


def cleanup_progress(scan_id: str):
    """Remove a completed scan from the store."""
    with _lock:
        _progress_store.pop(scan_id, None)
