from __future__ import annotations

import re
import subprocess

from network_scanner.config import AppSettings
from network_scanner.domain.models import ArpEntry

_INTERFACE_RE = re.compile(r"^Interface:\s+(?P<interface>\d+\.\d+\.\d+\.\d+)\s+---")
_ENTRY_RE = re.compile(
    r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\s+"
    r"(?P<type>\w+)\s*$"
)


def parse_arp_output(output: str) -> list[ArpEntry]:
    current_interface = ""
    entries: list[ArpEntry] = []
    for line in output.splitlines():
        interface_match = _INTERFACE_RE.match(line.strip())
        if interface_match:
            current_interface = interface_match.group("interface")
            continue
        entry_match = _ENTRY_RE.match(line)
        if not entry_match:
            continue
        entries.append(
            ArpEntry(
                interface_ip=current_interface,
                ip_address=entry_match.group("ip"),
                mac_address=entry_match.group("mac").lower(),
                entry_type=entry_match.group("type").lower(),
            )
        )
    return entries


class WindowsArpReader:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def read_entries(self) -> list[ArpEntry]:
        completed = subprocess.run(
            list(self.settings.arp_command),
            capture_output=True,
            text=True,
            timeout=self.settings.network_command_timeout_seconds,
            check=True,
        )
        return parse_arp_output(completed.stdout)
