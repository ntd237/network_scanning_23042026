from network_scanner.domain.ip_logic import build_candidate_hosts, build_excluded_ips, compute_free_ips, derive_network_details
from network_scanner.domain.models import AdapterInfo


def make_adapter() -> AdapterInfo:
    return AdapterInfo(
        interface_alias="Ethernet",
        interface_description="Intel",
        interface_index=7,
        interface_metric=15,
        ipv4_address="192.168.1.10",
        subnet_mask="255.255.255.0",
        prefix_length=24,
        network_address="192.168.1.0",
        broadcast_address="192.168.1.255",
        gateway="192.168.1.1",
        mac_address="aa-bb-cc-dd-ee-ff",
        status="Up",
    )


def test_derive_network_details() -> None:
    details = derive_network_details("192.168.1.10", 24)
    assert details == {
        "subnet_mask": "255.255.255.0",
        "network_address": "192.168.1.0",
        "broadcast_address": "192.168.1.255",
    }


def test_build_candidate_hosts_excludes_current_host() -> None:
    hosts = build_candidate_hosts(make_adapter())
    assert "192.168.1.10" not in hosts
    assert hosts[0] == "192.168.1.1"
    assert hosts[-1] == "192.168.1.254"


def test_compute_free_ips_excludes_reserved_and_used_hosts() -> None:
    adapter = make_adapter()
    all_hosts = build_candidate_hosts(adapter)
    excluded = build_excluded_ips(adapter)
    used = {"192.168.1.2", "192.168.1.5"}
    free_ips = compute_free_ips(all_hosts, used, excluded)
    assert "192.168.1.1" not in free_ips
    assert "192.168.1.10" not in free_ips
    assert "192.168.1.2" not in free_ips
    assert "192.168.1.5" not in free_ips
    assert "192.168.1.3" in free_ips
