from __future__ import annotations

from typing import Callable, Protocol

from network_scanner.domain.models import AdapterInfo, ArpEntry, PublicIpInfo


class AdapterProvider(Protocol):
    def list_adapters(self) -> list[AdapterInfo]:
        ...

    def choose_default_adapter(self, adapters: list[AdapterInfo]) -> AdapterInfo | None:
        ...


class PublicIpClient(Protocol):
    def fetch(self) -> PublicIpInfo:
        ...


class PingRunner(Protocol):
    def ping_hosts(
        self,
        hosts: list[str],
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> set[str]:
        ...


class ArpReader(Protocol):
    def read_entries(self) -> list[ArpEntry]:
        ...


class DnsResolver(Protocol):
    def resolve_many(
        self,
        ip_addresses: list[str],
        local_adapter: AdapterInfo | None = None,
    ) -> dict[str, str]:
        ...
