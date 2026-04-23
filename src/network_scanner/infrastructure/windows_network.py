from __future__ import annotations

import json
import subprocess
from typing import Any

from network_scanner.config import AppSettings
from network_scanner.domain.ip_logic import derive_network_details
from network_scanner.domain.models import AdapterInfo


def parse_adapter_payload(payload: str) -> list[AdapterInfo]:
    if not payload.strip():
        return []
    raw = json.loads(payload)
    items = raw if isinstance(raw, list) else [raw]
    adapters: list[AdapterInfo] = []
    for item in items:
        ipv4_address = item.get("IPv4Address")
        prefix_length = item.get("PrefixLength")
        if not ipv4_address or prefix_length is None:
            continue
        prefix_length = int(prefix_length)
        network_details = derive_network_details(ipv4_address, prefix_length)
        adapters.append(
            AdapterInfo(
                interface_alias=item.get("InterfaceAlias", ""),
                interface_description=item.get("InterfaceDescription", ""),
                interface_index=int(item.get("InterfaceIndex", 0)),
                interface_metric=int(item.get("InterfaceMetric", 9999)),
                ipv4_address=ipv4_address,
                subnet_mask=network_details["subnet_mask"],
                prefix_length=prefix_length,
                network_address=network_details["network_address"],
                broadcast_address=network_details["broadcast_address"],
                gateway=item.get("IPv4DefaultGateway"),
                mac_address=item.get("MacAddress"),
                status=item.get("Status", "Unknown"),
            )
        )
    return adapters


class WindowsAdapterProvider:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def list_adapters(self) -> list[AdapterInfo]:
        command = [
            self.settings.powershell_executable,
            *self.settings.powershell_common_flags,
            self.settings.get_adapters_script,
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.settings.network_command_timeout_seconds,
            check=True,
        )
        adapters = parse_adapter_payload(completed.stdout)
        return sorted(adapters, key=self._sort_key)

    def choose_default_adapter(self, adapters: list[AdapterInfo]) -> AdapterInfo | None:
        if not adapters:
            return None
        return min(adapters, key=self._sort_key)

    def _sort_key(self, adapter: AdapterInfo) -> tuple[int, int, int, str]:
        has_gateway = 0 if adapter.gateway else 1
        return (has_gateway, adapter.interface_metric, adapter.interface_index, adapter.interface_alias.lower())
