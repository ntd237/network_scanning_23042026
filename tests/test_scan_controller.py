from __future__ import annotations

from network_scanner.application.scan_controller import ScanController
from network_scanner.config import get_settings
from network_scanner.domain.models import AdapterInfo, ArpEntry, PublicIpInfo


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


class DummyAdapterProvider:
    def list_adapters(self) -> list[AdapterInfo]:
        return [make_adapter()]

    def choose_default_adapter(self, adapters: list[AdapterInfo]) -> AdapterInfo | None:
        return adapters[0] if adapters else None


class DummyPublicIpClient:
    def fetch(self) -> PublicIpInfo:
        return PublicIpInfo(ip="1.2.3.4", success=True)


class DummyPingRunner:
    def ping_hosts(self, hosts: list[str], progress_callback=None) -> set[str]:  # type: ignore[no-untyped-def]
        if progress_callback:
            progress_callback(len(hosts), len(hosts))
        return {"192.168.1.2"}


class DummyArpReader:
    def read_entries(self) -> list[ArpEntry]:
        return [
            ArpEntry(
                interface_ip="192.168.1.10",
                ip_address="192.168.1.2",
                mac_address="11-22-33-44-55-66",
                entry_type="dynamic",
            ),
            ArpEntry(
                interface_ip="192.168.1.10",
                ip_address="192.168.1.255",
                mac_address="ff-ff-ff-ff-ff-ff",
                entry_type="static",
            ),
        ]


class DummyDnsResolver:
    def resolve_many(self, ip_addresses: list[str], local_adapter: AdapterInfo | None = None) -> dict[str, str]:
        return {
            "192.168.1.10": "ntd237",
            "192.168.1.2": "Oppo Find X6",
        }


def test_scan_network_includes_local_device_and_excludes_broadcast_entry() -> None:
    settings = get_settings()
    controller = ScanController(
        settings=settings,
        adapter_provider=DummyAdapterProvider(),
        public_ip_client=DummyPublicIpClient(),
        ping_runner=DummyPingRunner(),
        arp_reader=DummyArpReader(),
        dns_resolver=DummyDnsResolver(),
    )

    summary = controller.scan_network(make_adapter(), "session-1")
    devices_by_ip = {device.ip_address: device for device in summary.devices}

    assert "192.168.1.10" in devices_by_ip
    assert devices_by_ip["192.168.1.10"].hostname == "ntd237"
    assert devices_by_ip["192.168.1.10"].source == "local"
    assert "192.168.1.2" in devices_by_ip
    assert devices_by_ip["192.168.1.2"].hostname == "Oppo Find X6"
    assert "192.168.1.255" not in devices_by_ip
