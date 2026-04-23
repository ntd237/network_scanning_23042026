from network_scanner.infrastructure.arp_parser import parse_arp_output


SAMPLE_ARP = """
Interface: 192.168.1.10 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.21          aa-bb-cc-dd-ee-ff     dynamic

Interface: 10.0.0.5 --- 0xf
  Internet Address      Physical Address      Type
  10.0.0.1              66-77-88-99-aa-bb     dynamic
""".strip()


def test_parse_arp_output_collects_entries() -> None:
    entries = parse_arp_output(SAMPLE_ARP)
    assert len(entries) == 3
    assert entries[0].interface_ip == "192.168.1.10"
    assert entries[0].ip_address == "192.168.1.1"
    assert entries[0].mac_address == "00-11-22-33-44-55"
    assert entries[2].interface_ip == "10.0.0.5"
