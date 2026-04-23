from __future__ import annotations

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt

from network_scanner.config import get_settings
from network_scanner.domain.models import DeviceInfo


class DeviceTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._devices: list[DeviceInfo] = []
        self._texts = get_settings().ui_text
        self.headers = (
            self._texts.table_header_ip,
            self._texts.table_header_mac,
            self._texts.table_header_hostname,
            self._texts.table_header_source,
        )

    def update_data(self, devices: list[DeviceInfo]) -> None:
        self.beginResetModel()
        self._devices = devices
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._devices)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> str | int | None:
        if not index.isValid():
            return None
        device = self._devices[index.row()]
        values = (
            device.ip_address,
            device.mac_address or self._texts.table_placeholder_value,
            device.hostname or self._texts.table_placeholder_value,
            self._format_source(device.source),
        )
        if role == Qt.DisplayRole:
            return values[index.column()]
        if role == Qt.TextAlignmentRole and index.column() == 3:
            return int(Qt.AlignCenter)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> str | None:
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.headers[section]
        return str(section + 1)

    def _format_source(self, source: str) -> str:
        mapping = {
            "ping": self._texts.source_ping,
            "arp": self._texts.source_arp,
            "ping+arp": self._texts.source_ping_arp,
            "local": self._texts.source_local,
        }
        return mapping.get(source.lower(), source or self._texts.table_placeholder_value)


class IpTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._ips: list[str] = []
        self._texts = get_settings().ui_text
        self.headers = (self._texts.table_header_free_ip,)

    def update_data(self, ip_addresses: list[str]) -> None:
        self.beginResetModel()
        self._ips = ip_addresses
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._ips)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return 1

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> str | None:
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        return self._ips[index.row()]

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> str | None:
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.headers[section]
        return str(section + 1)
