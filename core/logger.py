"""文件日志：将外联事件落盘为 CSV 和/或 JSON，方便事后回看。

用法：
    logger = EgressLogger(csv_path="egress.csv", json_path="egress.jsonl")
    logger.log(timestamp, proc, sni, dst, uplink_bytes, is_agent, alert_level)
    logger.close()
"""
from __future__ import annotations

import csv
import json
import os
import threading
import time
from dataclasses import dataclass, asdict


@dataclass
class EgressRecord:
    timestamp: str
    epoch: float
    proc: str
    sni: str
    dst: str
    uplink_bytes: int
    is_agent: bool
    alert_level: str  # "" / "warn" / "high" / "critical"


class EgressLogger:
    def __init__(self, csv_path: str | None = None, json_path: str | None = None):
        self.csv_path = csv_path
        self.json_path = json_path
        self._lock = threading.Lock()
        self._csv_fh = None
        self._csv_writer = None
        self._json_fh = None
        self._count = 0
        self._open()

    def _open(self):
        if self.csv_path:
            write_header = not os.path.exists(self.csv_path)
            self._csv_fh = open(self.csv_path, "a", newline="", encoding="utf-8")
            self._csv_writer = csv.writer(self._csv_fh)
            if write_header:
                self._csv_writer.writerow(
                    ["timestamp", "epoch", "proc", "sni", "dst", "uplink_bytes", "is_agent", "alert_level"]
                )
        if self.json_path:
            self._json_fh = open(self.json_path, "a", encoding="utf-8")

    def log(self, timestamp: str, epoch: float, proc: str, sni: str, dst: str,
            uplink_bytes: int, is_agent: bool, alert_level: str = "") -> None:
        rec = EgressRecord(timestamp, epoch, proc, sni, dst, uplink_bytes, is_agent, alert_level)
        with self._lock:
            if self._csv_writer:
                self._csv_writer.writerow([timestamp, epoch, proc, sni, dst, uplink_bytes, is_agent, alert_level])
                self._csv_fh.flush()
            if self._json_fh:
                self._json_fh.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
                self._json_fh.flush()
            self._count += 1

    @property
    def count(self) -> int:
        return self._count

    def close(self):
        with self._lock:
            if self._csv_fh:
                self._csv_fh.close()
            if self._json_fh:
                self._json_fh.close()
