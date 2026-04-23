from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Callable

from network_scanner.application.services import AdapterProvider, ArpReader, DnsResolver, PingRunner, PublicIpClient
from network_scanner.config import AppSettings
from network_scanner.domain.ip_logic import build_candidate_hosts, build_excluded_ips, compute_free_ips, is_large_subnet
from network_scanner.domain.models import AdapterInfo, DeviceInfo, PublicIpInfo, ScanProgress, ScanSummary


class ScanController:
    def __init__(
        self,
        settings: AppSettings,
        adapter_provider: AdapterProvider,
        public_ip_client: PublicIpClient,
        ping_runner: PingRunner,
        arp_reader: ArpReader,
        dns_resolver: DnsResolver,
    ) -> None:
        self.settings = settings
        self.adapter_provider = adapter_provider
        self.public_ip_client = public_ip_client
        self.ping_runner = ping_runner
        self.arp_reader = arp_reader
        self.dns_resolver = dns_resolver

    def load_adapters(self) -> tuple[list[AdapterInfo], AdapterInfo | None]:
        adapters = self.adapter_provider.list_adapters()
        return adapters, self.adapter_provider.choose_default_adapter(adapters)

    def fetch_public_ip(self) -> PublicIpInfo:
        return self.public_ip_client.fetch()

    def scan_network(
        self,
        adapter: AdapterInfo,
        session_id: str,
        progress_callback: Callable[[ScanProgress], None] | None = None,
    ) -> ScanSummary:
        started_at = datetime.now()
        candidate_hosts = build_candidate_hosts(adapter)
        excluded_ips = build_excluded_ips(adapter)

        if progress_callback:
            progress_callback(
                ScanProgress(
                    current=0,
                    total=len(candidate_hosts),
                    message="Đang chuẩn bị quét subnet...",
                )
            )

        def ping_progress(current: int, total: int) -> None:
            if progress_callback:
                progress_callback(
                    ScanProgress(
                        current=current,
                        total=total,
                        message=f"Đang ping {current}/{total} host...",
                    )
                )

        ping_hits = self.ping_runner.ping_hosts(candidate_hosts, progress_callback=ping_progress)
        arp_entries = self.arp_reader.read_entries()
        relevant_arp_entries = self._filter_entries_for_adapter(adapter, arp_entries)

        used_ips = set(ping_hits)
        used_ips.update(entry.ip_address for entry in relevant_arp_entries)

        ips_for_name_lookup = sorted(used_ips | {adapter.ipv4_address})
        hostname_map = self.dns_resolver.resolve_many(ips_for_name_lookup, local_adapter=adapter)
        devices = self._build_devices(adapter, sorted(used_ips), ping_hits, relevant_arp_entries, hostname_map)
        free_ips = compute_free_ips(candidate_hosts, used_ips, excluded_ips)

        warning_message = ""
        if is_large_subnet(adapter, self.settings.max_hosts_warning_threshold):
            warning_message = "Subnet lớn, thời gian quét có thể kéo dài."

        return ScanSummary(
            adapter=adapter,
            devices=devices,
            free_ips=free_ips,
            excluded_ips=sorted(excluded_ips),
            total_hosts=len(candidate_hosts),
            scanned_hosts=len(candidate_hosts),
            warning_message=warning_message,
            status_message=f"Phát hiện {len(devices)} thiết bị, {len(free_ips)} IP còn trống.",
            session_id=session_id,
            started_at=started_at,
            completed_at=datetime.now(),
        )

    def _filter_entries_for_adapter(self, adapter: AdapterInfo, entries: list) -> list:
        network = ipaddress.IPv4Network(f"{adapter.network_address}/{adapter.prefix_length}", strict=False)
        filtered = []
        for entry in entries:
            try:
                entry_ip = ipaddress.IPv4Address(entry.ip_address)
            except ipaddress.AddressValueError:
                continue
            if entry_ip not in network.hosts():
                continue
            if entry.ip_address == adapter.ipv4_address:
                continue
            if entry.mac_address == "ff-ff-ff-ff-ff-ff":
                continue
            if entry.entry_type == "invalid":
                continue
            if entry.ip_address != adapter.ipv4_address:
                filtered.append(entry)
        return filtered

    def _build_devices(
        self,
        adapter: AdapterInfo,
        used_ips: list[str],
        ping_hits: set[str],
        arp_entries: list,
        hostname_map: dict[str, str],
    ) -> list[DeviceInfo]:
        arp_map = {entry.ip_address: entry for entry in arp_entries}
        devices: list[DeviceInfo] = [
            DeviceInfo(
                ip_address=adapter.ipv4_address,
                mac_address=adapter.mac_address or "",
                hostname=hostname_map.get(adapter.ipv4_address, ""),
                source="local",
            )
        ]
        for ip_address in used_ips:
            arp_entry = arp_map.get(ip_address)
            if ip_address in ping_hits and arp_entry:
                source = "ping+arp"
            elif ip_address in ping_hits:
                source = "ping"
            else:
                source = "arp"
            devices.append(
                DeviceInfo(
                    ip_address=ip_address,
                    mac_address=arp_entry.mac_address if arp_entry else "",
                    hostname=hostname_map.get(ip_address, ""),
                    source=source,
                )
            )
        return sorted(devices, key=lambda item: tuple(int(part) for part in item.ip_address.split(".")))
