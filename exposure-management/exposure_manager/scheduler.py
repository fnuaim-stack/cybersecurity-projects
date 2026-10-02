from __future__ import annotations

import threading
import time


class ScanScheduler:
    def __init__(self, scanner, platform, *, poll_seconds: int = 20) -> None:
        self.scanner = scanner
        self.platform = platform
        self.poll_seconds = max(5, poll_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="exposure-scheduler")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run_due_once(self) -> list[dict]:
        launched = []
        for schedule in self.platform.due_schedules():
            try:
                job = self.scanner.start(
                    provider=schedule["provider"],
                    target=schedule["target"],
                    scope=schedule["scope"],
                    ports=schedule["ports"],
                    partial=bool(schedule["partial"]),
                )
            except Exception:
                # Keep the schedule due so the next poll can retry after the local tool/target issue is fixed.
                continue
            self.platform.mark_schedule_run(schedule["id"], job["id"])
            launched.append(job)
        return launched

    def _loop(self) -> None:
        while not self._stop.wait(self.poll_seconds):
            try:
                self.run_due_once()
            except Exception:
                # A scheduler failure must never take down the local UI.
                time.sleep(1)
