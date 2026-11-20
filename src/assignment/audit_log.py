"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
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
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Mở một entry: lưu input + thời điểm bắt đầu. Trả về request_id."""
        request_id = request_id or uuid.uuid4().hex
        self._open[request_id] = {
            "request_id": request_id,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "input": text,
            "_start": time.perf_counter(),
        }
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Đóng entry: lưu output (đã che secret), quyết định chặn, lớp chặn, latency."""
        entry = self._open.pop(request_id, None) if request_id else None
        if entry is None:
            entry = {
                "request_id": request_id or uuid.uuid4().hex,
                "user_id": user_id,
                "timestamp": utc_now_iso(),
                "input": None,
                "_start": None,
            }
        start = entry.pop("_start", None)
        latency_ms = (time.perf_counter() - start) * 1000 if start is not None else None

        # Log không được trở thành nơi lộ secret: che output và input trước khi lưu
        from guardrails.output_guardrails import content_filter

        if entry.get("input"):
            entry["input"] = content_filter(entry["input"])["redacted"]
        entry.update({
            "output": content_filter(text or "")["redacted"],
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
        })
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None) -> str:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
