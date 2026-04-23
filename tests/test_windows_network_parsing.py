import json

from network_scanner.infrastructure.windows_network import parse_adapter_payload


def test_parse_adapter_payload_reads_windows_adapter_json() -> None:
    payload = json.dumps(
        [
            {
                "InterfaceAlias": "Wi-Fi",
                "InterfaceDescription": "Intel Wi-Fi",
                "InterfaceIndex": 12,
                "InterfaceMetric": 25,
                "IPv4Address": "192.168.1.10",
                "PrefixLength": 24,
                "IPv4DefaultGateway": "192.168.1.1",
                "MacAddress": "AA-BB-CC-DD-EE-FF",
                "Status": "Up",
            }
        ]
    )

    adapters = parse_adapter_payload(payload)

    assert len(adapters) == 1
    adapter = adapters[0]
    assert adapter.interface_alias == "Wi-Fi"
    assert adapter.subnet_mask == "255.255.255.0"
    assert adapter.network_address == "192.168.1.0"
    assert adapter.broadcast_address == "192.168.1.255"
    assert adapter.gateway == "192.168.1.1"
