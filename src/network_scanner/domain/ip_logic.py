from __future__ import annotations

import ipaddress

from .models import AdapterInfo


def derive_network_details(ipv4_address: str, prefix_length: int) -> dict[str, str]:
    network = ipaddress.IPv4Interface(f"{ipv4_address}/{prefix_length}").network
    return {
        "subnet_mask": str(network.netmask),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
    }


def build_candidate_hosts(adapter: AdapterInfo) -> list[str]:
    network = ipaddress.IPv4Network(f"{adapter.network_address}/{adapter.prefix_length}", strict=False)
    current_ip = ipaddress.IPv4Address(adapter.ipv4_address)
    return [str(host) for host in network.hosts() if host != current_ip]


def build_excluded_ips(adapter: AdapterInfo) -> set[str]:
    excluded = {
        adapter.network_address,
        adapter.broadcast_address,
        adapter.ipv4_address,
    }
    if adapter.gateway:
        excluded.add(adapter.gateway)
    return excluded


def compute_free_ips(all_hosts: list[str], used_ips: set[str], excluded_ips: set[str]) -> list[str]:
    free_ips = [ip for ip in all_hosts if ip not in used_ips and ip not in excluded_ips]
    return sorted(free_ips, key=lambda value: tuple(int(part) for part in value.split(".")))


def is_large_subnet(adapter: AdapterInfo, threshold: int) -> bool:
    return len(build_candidate_hosts(adapter)) > threshold
