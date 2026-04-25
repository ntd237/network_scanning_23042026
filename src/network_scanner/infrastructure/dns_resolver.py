from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from urllib import error, parse, request

from network_scanner.config import AppSettings
from network_scanner.domain.models import AdapterInfo

_PING_NAME_RE = re.compile(r"^Pinging\s+(?P<name>.+?)\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\]", re.IGNORECASE)
_NBTSTAT_NAME_RE = re.compile(
    r"^\s*(?P<name>[^\s<].*?)\s+<00>\s+UNIQUE\s+Registered\s*$",
    re.IGNORECASE,
)
_HTML_TITLE_RE = re.compile(r"<title[^>]*>(?P<title>.*?)</title>", re.IGNORECASE | re.DOTALL)
_ROUTER_ANONYMOUS_NAMES = {"anonymous host", "匿名主机"}
_ROUTER_PASSWORD_SECRET = "RDpbLfCPsJZ7fiv"
_ROUTER_PASSWORD_DICTIONARY = (
    "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAU"
    "w0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal"
    "1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
)


class SocketDnsResolver:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self._router_name_cache: dict[str, dict[str, str]] = {}

    def resolve_many(
        self,
        ip_addresses: list[str],
        local_adapter: AdapterInfo | None = None,
    ) -> dict[str, str]:
        if not self.settings.reverse_dns_enabled or not ip_addresses:
            return {}

        hostnames: dict[str, str] = {}
        if local_adapter:
            local_hostname = self._normalize_name(self._resolve_local_hostname())
            if local_hostname:
                hostnames[local_adapter.ipv4_address] = local_hostname
            hostnames.update(self._lookup_router_client_names(ip_addresses, local_adapter))

        unresolved_ips = [ip_address for ip_address in ip_addresses if ip_address not in hostnames]
        if not unresolved_ips:
            return hostnames

        max_workers = min(self.settings.name_resolution_max_workers, max(1, len(unresolved_ips)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._resolve_one, ip_address, local_adapter): ip_address for ip_address in unresolved_ips
            }
            for future in as_completed(future_map):
                ip_address = future_map[future]
                try:
                    hostname = future.result()
                except Exception:
                    hostname = ""
                if hostname:
                    hostnames[ip_address] = hostname
        return hostnames

    def _resolve_one(self, ip_address: str, local_adapter: AdapterInfo | None = None) -> str:
        if local_adapter and ip_address == local_adapter.ipv4_address:
            return self._normalize_name(self._resolve_local_hostname())

        for candidate in (
            self._reverse_dns_lookup(ip_address),
            self._multicast_name_lookup(ip_address, local_adapter),
            self._ping_name_lookup(ip_address),
            self._netbios_lookup(ip_address),
            self._http_title_lookup(ip_address, local_adapter),
            self._windows_known_device_lookup(ip_address),
        ):
            normalized = self._normalize_name(candidate)
            if normalized:
                return normalized
        return ""

    def _lookup_router_client_names(
        self,
        ip_addresses: list[str],
        local_adapter: AdapterInfo | None,
    ) -> dict[str, str]:
        if (
            not self.settings.router_name_resolution_enabled
            or not local_adapter
            or not local_adapter.gateway
            or not self.settings.router_password
        ):
            return {}

        gateway = local_adapter.gateway
        if gateway not in self._router_name_cache:
            self._router_name_cache[gateway] = self._fetch_router_client_names(local_adapter)

        router_names = self._router_name_cache.get(gateway, {})
        return {ip_address: router_names[ip_address] for ip_address in ip_addresses if ip_address in router_names}

    def _fetch_router_client_names(self, local_adapter: AdapterInfo) -> dict[str, str]:
        stok = self._login_to_router(local_adapter.gateway or "")
        if not stok or not local_adapter.gateway:
            return {}

        payload = {
            "method": "get",
            "hosts_info": {"table": "device"},
            "dhcpd": {"name": "dhcp_clients"},
            "ip_mac_bind": {"name": "sys_arp"},
        }
        response = self._send_router_request(
            f"http://{local_adapter.gateway}/stok={parse.quote(stok)}/ds",
            payload,
        )
        if not response or _extract_router_error_code(response) != 0:
            return {}

        client_names: dict[str, str] = {}
        for row in _flatten_router_rows(response.get("hosts_info", {}).get("device")):
            self._update_router_name_map(client_names, row)
        for row in _flatten_router_rows(response.get("dhcpd", {}).get("dhcp_clients")):
            self._update_router_name_map(client_names, row)
        for row in _flatten_router_rows(response.get("ip_mac_bind", {}).get("sys_arp")):
            self._update_router_name_map(client_names, row)
        return client_names

    def _login_to_router(self, gateway_ip: str) -> str:
        if not gateway_ip or not self.settings.router_password:
            return ""

        login_payloads = []
        encoded_password = encode_router_password(self.settings.router_password)
        candidate_passwords = [encoded_password]
        if encoded_password != self.settings.router_password:
            candidate_passwords.append(self.settings.router_password)

        for candidate_password in candidate_passwords:
            login_body: dict[str, object] = {"password": candidate_password}
            if self.settings.router_username:
                login_body["username"] = self.settings.router_username
            login_payloads.append({"method": "do", "login": login_body})

        for path in self.settings.router_query_paths:
            url = f"http://{gateway_ip}{path}"
            for payload in login_payloads:
                response = self._send_router_request(url, payload)
                if not response or _extract_router_error_code(response) != 0:
                    continue
                stok = str(response.get("stok", "")).strip()
                if stok:
                    return stok
        return ""

    def _send_router_request(self, url: str, payload: dict[str, object]) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        request_object = request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": "NetworkScanner/1.0",
            },
        )
        try:
            with request.urlopen(
                request_object,
                timeout=self.settings.router_name_resolution_timeout_seconds,
            ) as response:
                raw_payload = response.read().decode("utf-8", "ignore")
        except (error.HTTPError, error.URLError, OSError, TimeoutError, ValueError):
            return {}

        try:
            parsed_payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            return {}
        return parsed_payload if isinstance(parsed_payload, dict) else {}

    def _update_router_name_map(self, client_names: dict[str, str], row: dict[str, object]) -> None:
        ip_address = _extract_router_ip_address(row)
        candidate_name = self._normalize_name(_extract_router_client_name(row))
        if not ip_address or not candidate_name:
            return
        if ip_address not in client_names or client_names[ip_address].lower() in _ROUTER_ANONYMOUS_NAMES:
            client_names[ip_address] = candidate_name

    def _reverse_dns_lookup(self, ip_address: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.gaierror, socket.herror, OSError):
            return ""

    def _windows_known_device_lookup(self, ip_address: str) -> str:
        if not self.settings.windows_known_device_name_resolution_enabled:
            return ""
        try:
            safe_ip_address = str(ipaddress.IPv4Address(ip_address))
        except ipaddress.AddressValueError:
            return ""

        command = [
            self.settings.powershell_executable,
            *self.settings.powershell_common_flags,
            f"& {{ {self.settings.windows_known_device_name_script} }} -IpAddress {safe_ip_address}",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.settings.windows_known_device_name_command_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if completed.returncode != 0 or not completed.stdout.strip():
            return ""

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return ""
        if not isinstance(payload, dict):
            return ""
        return choose_windows_known_device_label(
            _ensure_string_list(payload.get("KnownDeviceLabels")),
            _ensure_dict_list(payload.get("Processes")),
        )

    def _multicast_name_lookup(self, ip_address: str, local_adapter: AdapterInfo | None = None) -> str:
        if not self.settings.multicast_name_resolution_enabled:
            return ""

        reverse_name = build_reverse_dns_name(ip_address)
        if not reverse_name:
            return ""

        endpoints = (
            (self.settings.mdns_multicast_address, self.settings.mdns_port),
            (self.settings.llmnr_multicast_address, self.settings.llmnr_port),
        )
        for multicast_address, port in endpoints:
            hostname = self._multicast_ptr_lookup(reverse_name, multicast_address, port, local_adapter)
            if hostname:
                return hostname
        return ""

    def _multicast_ptr_lookup(
        self,
        reverse_name: str,
        multicast_address: str,
        port: int,
        local_adapter: AdapterInfo | None = None,
    ) -> str:
        query = build_dns_ptr_query(reverse_name)
        for _ in range(max(1, self.settings.multicast_name_resolution_attempts)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                    sock.settimeout(self.settings.multicast_name_resolution_timeout_seconds)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                    if local_adapter and local_adapter.ipv4_address:
                        sock.setsockopt(
                            socket.IPPROTO_IP,
                            socket.IP_MULTICAST_IF,
                            socket.inet_aton(local_adapter.ipv4_address),
                        )
                    sock.sendto(query, (multicast_address, port))
                    while True:
                        payload, _ = sock.recvfrom(4096)
                        hostname = parse_dns_ptr_response(payload, reverse_name)
                        if hostname:
                            return hostname
            except (OSError, TimeoutError, ValueError):
                continue
        return ""

    def _ping_name_lookup(self, ip_address: str) -> str:
        if not self.settings.ping_name_resolution_enabled:
            return ""
        command = [
            part.format(timeout_ms=self.settings.ping_timeout_ms, ip=ip_address)
            for part in self.settings.ping_name_command_template
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.settings.name_resolution_command_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return parse_ping_name_output(completed.stdout, ip_address)

    def _netbios_lookup(self, ip_address: str) -> str:
        if not self.settings.netbios_name_resolution_enabled:
            return ""
        command = [part.format(ip=ip_address) for part in self.settings.netbios_command_template]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.settings.name_resolution_command_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return parse_nbtstat_output(completed.stdout)

    def _http_title_lookup(self, ip_address: str, local_adapter: AdapterInfo | None = None) -> str:
        if not self.settings.http_title_probe_enabled:
            return ""
        if local_adapter and local_adapter.gateway and ip_address != local_adapter.gateway:
            return ""

        ssl_context = ssl._create_unverified_context()
        for url_template in self.settings.http_title_probe_urls:
            try:
                with request.urlopen(
                    url_template.format(ip=ip_address),
                    timeout=self.settings.http_title_probe_timeout_seconds,
                    context=ssl_context,
                ) as response:
                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" not in content_type and content_type:
                        continue
                    payload = response.read(8192).decode("utf-8", "ignore")
            except (error.URLError, OSError, TimeoutError, ValueError):
                continue
            title = extract_html_title(payload)
            if title:
                return title
        return ""

    def _resolve_local_hostname(self) -> str:
        return os.environ.get("COMPUTERNAME", "").strip() or socket.gethostname().strip()

    def _normalize_name(self, value: str) -> str:
        cleaned = value.strip().strip(".")
        if not cleaned:
            return ""
        if cleaned.lower().endswith(".local"):
            cleaned = cleaned[:-6]
        if "." in cleaned and " " not in cleaned:
            cleaned = cleaned.split(".", 1)[0]
        return cleaned.strip()


def parse_ping_name_output(output: str, ip_address: str) -> str:
    for line in output.splitlines():
        match = _PING_NAME_RE.match(line.strip())
        if not match:
            continue
        resolved_ip = match.group("ip").strip()
        resolved_name = match.group("name").strip()
        if resolved_ip == ip_address and resolved_name != ip_address:
            return resolved_name
    return ""


def parse_nbtstat_output(output: str) -> str:
    for line in output.splitlines():
        match = _NBTSTAT_NAME_RE.match(line.rstrip())
        if match:
            return match.group("name").strip()
    return ""


def choose_windows_known_device_label(labels: list[str], processes: list[dict[str, object]]) -> str:
    unique_labels = sorted({label.strip() for label in labels if label and label.strip()})
    if not unique_labels or not processes:
        return ""

    best_label = ""
    best_score = 0
    tied = False
    for label in unique_labels:
        label_tokens = _name_tokens(label)
        if not label_tokens:
            continue
        score = 0
        for process in processes:
            company_tokens = _name_tokens(str(process.get("CompanyName", "")))
            process_tokens = _name_tokens(str(process.get("ProcessName", "")))
            product_tokens = _name_tokens(str(process.get("ProductName", "")))
            path_tokens = _name_tokens(str(process.get("Path", "")))
            score += 10 * len(label_tokens & company_tokens)
            score += 4 * len(label_tokens & process_tokens)
            score += 4 * len(label_tokens & product_tokens)
            score += len(label_tokens & path_tokens)
        if score > best_score:
            best_label = label
            best_score = score
            tied = False
        elif score == best_score and score > 0:
            tied = True

    return best_label if best_score >= 10 and not tied else ""


def _ensure_string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _ensure_dict_list(value: object) -> list[dict[str, object]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _name_tokens(value: str) -> set[str]:
    ignored_tokens = {"app", "connect", "daemon", "exe", "files", "program", "service", "windows"}
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) >= 2 and token not in ignored_tokens
    }


def build_reverse_dns_name(ip_address: str) -> str:
    try:
        address = socket.inet_aton(ip_address)
    except OSError:
        return ""
    return ".".join(str(part) for part in reversed(address)) + ".in-addr.arpa"


def build_dns_ptr_query(name: str) -> bytes:
    encoded_name = encode_dns_name(name)
    return struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + encoded_name + struct.pack("!HH", 12, 1)


def encode_dns_name(name: str) -> bytes:
    encoded = bytearray()
    for label in name.strip(".").split("."):
        raw_label = label.encode("ascii", "ignore")
        if not raw_label or len(raw_label) > 63:
            return b""
        encoded.append(len(raw_label))
        encoded.extend(raw_label)
    encoded.append(0)
    return bytes(encoded)


def parse_dns_ptr_response(payload: bytes, expected_name: str) -> str:
    if len(payload) < 12:
        return ""
    try:
        _, _, question_count, answer_count, authority_count, additional_count = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return ""

    offset = 12
    expected = expected_name.strip(".").lower()
    for _ in range(question_count):
        question_name, offset = read_dns_name(payload, offset)
        if not question_name or offset + 4 > len(payload):
            return ""
        offset += 4
        if question_name.strip(".").lower() != expected:
            return ""

    record_count = answer_count + authority_count + additional_count
    for _ in range(record_count):
        record_name, offset = read_dns_name(payload, offset)
        if offset + 10 > len(payload):
            return ""
        record_type, _, _, data_length = struct.unpack("!HHIH", payload[offset : offset + 10])
        offset += 10
        data_offset = offset
        offset += data_length
        if offset > len(payload):
            return ""
        if record_name.strip(".").lower() != expected:
            continue
        if record_type != 12:
            continue
        ptr_name, _ = read_dns_name(payload, data_offset)
        if ptr_name:
            return ptr_name
    return ""


def read_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset = offset
    jumped = False
    visited_offsets: set[int] = set()

    while cursor < len(payload):
        if cursor in visited_offsets:
            return "", offset
        visited_offsets.add(cursor)

        length = payload[cursor]
        if length == 0:
            cursor += 1
            if not jumped:
                next_offset = cursor
            return ".".join(labels), next_offset

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(payload):
                return "", offset
            pointer = ((length & 0x3F) << 8) | payload[cursor + 1]
            if not jumped:
                next_offset = cursor + 2
            cursor = pointer
            jumped = True
            continue

        if length & 0xC0:
            return "", offset
        cursor += 1
        end = cursor + length
        if end > len(payload):
            return "", offset
        labels.append(payload[cursor:end].decode("utf-8", "ignore"))
        cursor = end

    return "", offset


def extract_html_title(payload: str) -> str:
    match = _HTML_TITLE_RE.search(payload)
    if not match:
        return ""
    title = unescape(match.group("title"))
    title = re.sub(r"\s+", " ", title).strip()
    return title


def encode_router_password(password: str) -> str:
    encoded: list[str] = []
    limit = max(len(_ROUTER_PASSWORD_SECRET), len(password))
    dictionary_length = len(_ROUTER_PASSWORD_DICTIONARY)
    for index in range(limit):
        left = 187
        right = 187
        if index >= len(_ROUTER_PASSWORD_SECRET):
            right = ord(password[index])
        elif index >= len(password):
            left = ord(_ROUTER_PASSWORD_SECRET[index])
        else:
            left = ord(_ROUTER_PASSWORD_SECRET[index])
            right = ord(password[index])
        encoded.append(_ROUTER_PASSWORD_DICTIONARY[(left ^ right) % dictionary_length])
    return "".join(encoded)


def _extract_router_error_code(payload: dict[str, object]) -> int:
    for key in ("error_code", "err_code"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def _flatten_router_rows(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if any(key in payload for key in ("ip", "ipaddr", "ip_address", "hostname", "name", "orgHostName")):
            return [payload]
        return [item for item in payload.values() if isinstance(item, dict)]
    return []


def _extract_router_ip_address(row: dict[str, object]) -> str:
    for key in ("ip", "ipaddr", "ip_address"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_router_client_name(row: dict[str, object]) -> str:
    for key in ("name", "hostname", "orgHostName", "device_name", "alias", "model"):
        value = row.get(key)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned and cleaned.lower() not in _ROUTER_ANONYMOUS_NAMES:
                return cleaned
    return ""
