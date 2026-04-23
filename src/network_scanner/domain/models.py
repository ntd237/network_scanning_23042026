from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class AdapterInfo:
    interface_alias: str
    interface_description: str
    interface_index: int
    interface_metric: int
    ipv4_address: str
    subnet_mask: str
    prefix_length: int
    network_address: str
    broadcast_address: str
    gateway: str | None = None
    mac_address: str | None = None
    status: str = "Unknown"

    @property
    def adapter_id(self) -> str:
        return f"{self.interface_index}:{self.interface_alias}"

    @property
    def cidr(self) -> str:
        return f"{self.ipv4_address}/{self.prefix_length}"


@dataclass(frozen=True)
class PublicIpInfo:
    ip: str = ""
    provider: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    org: str = ""
    status_message: str = ""
    success: bool = False


@dataclass(frozen=True)
class ArpEntry:
    interface_ip: str
    ip_address: str
    mac_address: str
    entry_type: str


@dataclass(frozen=True)
class DeviceInfo:
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    source: str = ""


@dataclass(frozen=True)
class ScanProgress:
    current: int
    total: int
    message: str = ""


@dataclass
class ScanSummary:
    adapter: AdapterInfo
    devices: list[DeviceInfo] = field(default_factory=list)
    free_ips: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)
    total_hosts: int = 0
    scanned_hosts: int = 0
    warning_message: str = ""
    status_message: str = ""
    session_id: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
