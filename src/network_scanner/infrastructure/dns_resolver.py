from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from network_scanner.config import AppSettings


class SocketDnsResolver:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def resolve_many(self, ip_addresses: list[str]) -> dict[str, str]:
        if not self.settings.reverse_dns_enabled or not ip_addresses:
            return {}

        hostnames: dict[str, str] = {}
        max_workers = min(16, len(ip_addresses))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(self._resolve_one, ip_address): ip_address for ip_address in ip_addresses}
            for future in as_completed(future_map):
                ip_address = future_map[future]
                try:
                    hostname = future.result()
                except Exception:
                    hostname = ""
                if hostname:
                    hostnames[ip_address] = hostname
        return hostnames

    def _resolve_one(self, ip_address: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.gaierror, socket.herror, OSError):
            return ""
