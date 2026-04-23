from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from network_scanner.config import AppSettings


class WindowsPingRunner:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def ping_hosts(
        self,
        hosts: list[str],
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> set[str]:
        if not hosts:
            return set()

        alive_hosts: set[str] = set()
        total = len(hosts)
        completed_count = 0

        max_workers = min(self.settings.scan_max_workers, max(1, total))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(self._ping_host, host): host for host in hosts}
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    if future.result():
                        alive_hosts.add(host)
                except Exception:
                    pass
                completed_count += 1
                if progress_callback:
                    progress_callback(completed_count, total)
        return alive_hosts

    def _ping_host(self, host: str) -> bool:
        command = [
            part.format(count=self.settings.ping_count, timeout_ms=self.settings.ping_timeout_ms, ip=host)
            for part in self.settings.ping_command_template
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.settings.network_command_timeout_seconds,
            check=False,
        )
        return result.returncode == 0
