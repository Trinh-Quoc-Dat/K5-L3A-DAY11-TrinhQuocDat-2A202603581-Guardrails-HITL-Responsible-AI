
"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(
        self,
        *,
        user_id: str,
        text: str,
        request_id: str | None = None,
    ):
        """Store input and start timestamp keyed by request_id/user_id."""

        key = request_id or user_id
        self._open[key] = time.monotonic()

        self.logs.append({
            "event": "input",
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": request_id,
            "input": text,
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, and latency."""

        key = request_id or user_id
        start_time = self._open.pop(key, None)

        latency_ms = None
        if start_time is not None:
            latency_ms = round(
                (time.monotonic() - start_time) * 1000,
                2,
            )

        self.logs.append({
            "event": "output",
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": request_id,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk as a JSON array."""

        path = Path(filepath or default_audit_log_path())

        # Create the output directory if it does not exist.
        path.parent.mkdir(parents=True, exist_ok=True)

        # Export all recorded events.
        with path.open("w", encoding="utf-8") as file:
            json.dump(
                self.logs,
                file,
                ensure_ascii=False,
                indent=2,
            )

        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
