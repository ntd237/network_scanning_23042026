from network_scanner.infrastructure.dns_resolver import (
    _extract_router_client_name,
    _extract_router_ip_address,
    _flatten_router_rows,
    encode_router_password,
    extract_html_title,
    parse_nbtstat_output,
    parse_ping_name_output,
)


def test_parse_ping_name_output_returns_resolved_host() -> None:
    output = """
Pinging ntd237 [192.168.1.10] with 32 bytes of data:
Reply from 192.168.1.10: bytes=32 time<1ms TTL=128
""".strip()

    assert parse_ping_name_output(output, "192.168.1.10") == "ntd237"


def test_parse_nbtstat_output_returns_unique_name() -> None:
    output = """
NetBIOS Remote Machine Name Table

       Name               Type         Status
    ---------------------------------------------
    NTD237         <00>  UNIQUE      Registered
    WORKGROUP      <00>  GROUP       Registered
""".strip()

    assert parse_nbtstat_output(output) == "NTD237"


def test_extract_html_title_returns_clean_title() -> None:
    payload = "<html><head><title>  Oppo Find X6  </title></head><body></body></html>"

    assert extract_html_title(payload) == "Oppo Find X6"


def test_encode_router_password_matches_router_algorithm() -> None:
    assert encode_router_password("admin") == "WaQ7xbhc9TefbwK"


def test_flatten_router_rows_accepts_table_dict() -> None:
    payload = {
        "row_1": {"ip": "192.168.1.2", "name": "Oppo Find X6"},
        "row_2": {"ip": "192.168.1.3", "hostname": "NTD237"},
    }

    rows = _flatten_router_rows(payload)

    assert len(rows) == 2
    assert rows[0]["ip"] == "192.168.1.2"


def test_extract_router_name_prefers_friendly_name_over_anonymous_hostname() -> None:
    row = {
        "ip": "192.168.1.2",
        "name": "Oppo Find X6",
        "hostname": "匿名主机",
    }

    assert _extract_router_ip_address(row) == "192.168.1.2"
    assert _extract_router_client_name(row) == "Oppo Find X6"
