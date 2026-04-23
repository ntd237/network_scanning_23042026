from __future__ import annotations

import os
from dataclasses import dataclass, field


def _get_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_str_env(name: str) -> str:
    return os.environ.get(name, "").strip()


@dataclass(frozen=True)
class UiText:
    window_title: str = "Bảng điều khiển quét mạng"
    hero_badge: str = "Windows • PyQt5"
    hero_title: str = "Quét mạng LAN"
    hero_subtitle: str = "Theo dõi adapter, public IP và danh sách thiết bị trong giao diện tập trung vào dữ liệu quét."
    control_panel_title: str = "Điều khiển quét"
    control_panel_subtitle: str = "Chọn adapter, làm mới dữ liệu rồi bắt đầu phiên quét."
    adapter_label: str = "Adapter"
    refresh_adapters_button: str = "Làm mới adapter"
    refresh_public_ip_button: str = "Cập nhật public IP"
    scan_button: str = "Quét mạng LAN"
    info_panel_title: str = "Thông tin mạng"
    info_panel_subtitle: str = "Chi tiết adapter đang chọn và public IP hiện tại."
    progress_panel_title: str = "Tiến trình"
    progress_panel_subtitle: str = "Trạng thái của phiên quét hiện tại."
    results_panel_title: str = "Kết quả quét"
    results_panel_subtitle: str = "Khu vực ưu tiên để xem thiết bị phát hiện được và các IP còn khả dụng."
    summary_panel_title: str = "Tóm tắt phiên quét"
    summary_panel_subtitle: str = "Thông tin tổng hợp sau khi quét xong."
    devices_tab_title: str = "Thiết bị phát hiện"
    free_ips_tab_title: str = "IP còn trống"
    summary_tab_title: str = "Tóm tắt"
    info_field_adapter: str = "Adapter"
    info_field_ipv4: str = "IPv4 nội bộ"
    info_field_subnet: str = "Subnet mask"
    info_field_cidr: str = "CIDR"
    info_field_network: str = "Network"
    info_field_broadcast: str = "Broadcast"
    info_field_gateway: str = "Gateway"
    info_field_public_ip: str = "Public IP"
    info_field_public_status: str = "Trạng thái"
    stat_adapter_label: str = "Adapter chính"
    stat_public_ip_label: str = "Public IP"
    stat_device_count_label: str = "Thiết bị hoạt động"
    stat_free_ip_count_label: str = "IP còn trống"
    ready_status: str = "Sẵn sàng quét mạng."
    adapter_loading_status: str = "Đang tải danh sách adapter..."
    adapter_loaded_status: str = "Đã cập nhật danh sách adapter."
    adapter_not_found_status: str = "Không tìm thấy adapter IPv4 hợp lệ."
    adapter_load_error_prefix: str = "Không thể tải adapter"
    public_ip_loading_status: str = "Đang cập nhật..."
    public_ip_unavailable: str = "Chưa có dữ liệu"
    invalid_adapter_error: str = "Chưa có adapter hợp lệ để quét."
    scan_starting_status: str = "Đang khởi tạo phiên quét..."
    generic_error_status: str = "Có lỗi xảy ra."
    error_dialog_title: str = "Lỗi"
    summary_empty_title: str = "Chưa có phiên quét"
    summary_empty_body: str = "Nhấn “Quét mạng LAN” để xem danh sách thiết bị phát hiện và các IP còn trống."
    summary_label_adapter: str = "Adapter"
    summary_label_local_ipv4: str = "IPv4 nội bộ"
    summary_label_gateway: str = "Gateway"
    summary_label_started_at: str = "Bắt đầu"
    summary_label_completed_at: str = "Kết thúc"
    summary_label_total_hosts: str = "Tổng số host"
    summary_label_device_count: str = "Thiết bị phát hiện"
    summary_label_free_ip_count: str = "IP còn trống"
    summary_label_excluded_ips: str = "IP loại trừ"
    summary_label_warning: str = "Cảnh báo"
    summary_label_status: str = "Trạng thái"
    table_header_ip: str = "IP"
    table_header_mac: str = "MAC"
    table_header_hostname: str = "Hostname"
    table_header_source: str = "Nguồn phát hiện"
    table_header_free_ip: str = "Địa chỉ IP khả dụng"
    table_placeholder_value: str = "—"
    source_ping: str = "Ping"
    source_arp: str = "ARP"
    source_ping_arp: str = "Ping + ARP"
    source_local: str = "Thiết bị hiện tại"
    card_hint_public_ip: str = "Đồng bộ từ Internet"
    card_hint_scan: str = "Ưu tiên hiển thị vùng quét"


@dataclass(frozen=True)
class UiTheme:
    window_width: int = 1320
    window_height: int = 960
    app_margin: int = 16
    app_spacing: int = 12
    section_spacing: int = 10
    header_maximum_height: int = 74
    info_panel_minimum_width: int = 360
    results_panel_minimum_height: int = 420
    control_button_min_width: int = 130
    control_row_height: int = 40
    adapter_combo_minimum_contents_length: int = 18
    summary_panel_minimum_height: int = 260
    splitter_left_initial: int = 980
    splitter_right_initial: int = 340
    body_font_family: str = "Segoe UI"
    heading_font_family: str = "Bahnschrift"
    body_font_size: int = 10
    heading_font_size: int = 17
    stylesheet: str = """
QWidget#AppRoot {
    background-color: #eef3f8;
}
QFrame#HeaderCard {
    background-color: #ffffff;
    border: 1px solid #d8e1ea;
    border-radius: 14px;
}
QFrame#PanelCard, QFrame#StatCard {
    background-color: #ffffff;
    border: 1px solid #d7e0ea;
    border-radius: 14px;
}
QLabel#HeroBadge {
    color: #1d5b79;
    background-color: #e7f0f6;
    border-radius: 10px;
    padding: 4px 10px;
    font-weight: 600;
}
QLabel#HeroTitle {
    color: #18324e;
    font-size: 22px;
    font-weight: 700;
}
QLabel#HeroSubtitle {
    color: #637689;
    font-size: 12px;
}
QLabel#PanelTitle {
    color: #17324e;
    font-size: 15px;
    font-weight: 700;
}
QLabel#PanelSubtitle {
    color: #66788d;
    font-size: 12px;
}
QLabel#FieldLabel {
    color: #64768a;
    font-size: 11px;
    font-weight: 600;
}
QLabel#FieldValue {
    color: #12263a;
    font-size: 13px;
    font-weight: 600;
}
QLabel#StatLabel {
    color: #698095;
    font-size: 11px;
    font-weight: 600;
}
QLabel#StatValue {
    color: #14324a;
    font-size: 18px;
    font-weight: 700;
}
QLabel#StatHint {
    color: #8595a5;
    font-size: 11px;
}
QComboBox {
    min-height: 40px;
    border: 1px solid #cfd9e4;
    border-radius: 12px;
    background-color: #ffffff;
    padding: 0 12px;
    color: #16324d;
}
QComboBox::drop-down {
    width: 28px;
    border: none;
}
QPushButton {
    min-height: 40px;
    padding: 0 16px;
    border-radius: 12px;
    border: 1px solid #cfd9e4;
    background-color: #f7fafc;
    color: #18324e;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #eef4f9;
}
QPushButton#PrimaryButton {
    background-color: #1d5b79;
    border-color: #1d5b79;
    color: #ffffff;
}
QPushButton#PrimaryButton:hover {
    background-color: #184c66;
}
QPushButton:disabled {
    background-color: #eef2f5;
    border-color: #d6dfe8;
    color: #95a4b3;
}
QProgressBar {
    min-height: 14px;
    border-radius: 7px;
    border: none;
    background-color: #e3ebf3;
    text-align: center;
}
QProgressBar::chunk {
    border-radius: 7px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2b7a9b, stop:1 #42b6b0);
}
QSplitter::handle {
    background-color: transparent;
}
QTabWidget::tab-bar {
    left: 12px;
}
QTabWidget::pane {
    border: none;
    background-color: transparent;
    top: 0px;
    margin-top: 10px;
}
QTabBar::tab {
    min-width: 150px;
    padding: 10px 16px;
    margin-right: 6px;
    margin-bottom: 0px;
    border: 1px solid #dbe4ed;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    background-color: #eaf0f5;
    color: #5c7086;
    font-weight: 600;
}
QTabBar::tab:selected {
    background-color: #ffffff;
    color: #17324e;
    border-color: #dbe4ed;
}
QTabBar::tab:hover {
    background-color: #f3f7fb;
    color: #17324e;
}
QTableView {
    border: none;
    background-color: #ffffff;
    alternate-background-color: #f7fafc;
    selection-background-color: #dcedf9;
    selection-color: #10263d;
    gridline-color: #eef3f7;
    padding: 4px;
}
QHeaderView::section {
    background-color: #f3f7fb;
    color: #5b7085;
    border: none;
    border-bottom: 1px solid #dbe4ed;
    padding: 12px 10px;
    font-weight: 700;
}
QTextEdit {
    border: 1px solid #dbe4ed;
    border-radius: 14px;
    background-color: #fbfdff;
    color: #17324e;
    padding: 8px;
}
QStatusBar {
    background-color: #ffffff;
    border-top: 1px solid #dbe4ed;
    color: #5a6f84;
}
QLabel#MutedText {
    color: #6f8294;
    font-size: 11px;
}
QMessageBox {
    background-color: #ffffff;
}
""".strip()


@dataclass(frozen=True)
class AppSettings:
    public_ip_url: str = "https://api.ipify.org?format=json"
    public_ip_timeout_seconds: float = 5.0
    network_command_timeout_seconds: float = 15.0
    ping_count: int = 1
    ping_timeout_ms: int = 700
    scan_max_workers: int = 64
    auto_select_strategy: str = "lowest_metric_with_gateway"
    dns_lookup_timeout_seconds: float = 1.5
    name_resolution_max_workers: int = 8
    name_resolution_command_timeout_seconds: float = 2.0
    max_hosts_warning_threshold: int = 512
    powershell_executable: str = "powershell"
    powershell_common_flags: tuple[str, ...] = (
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
    )
    get_adapters_script: str = """
$ErrorActionPreference = 'Stop'
$items = Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address -ne $null } |
    ForEach-Object {
        [PSCustomObject]@{
            InterfaceAlias = $_.InterfaceAlias
            InterfaceDescription = $_.NetAdapter.InterfaceDescription
            InterfaceIndex = $_.InterfaceIndex
            InterfaceMetric = if ($_.NetIPv4Interface) { $_.NetIPv4Interface.InterfaceMetric } else { 9999 }
            IPv4Address = $_.IPv4Address.IPAddress
            PrefixLength = $_.IPv4Address.PrefixLength
            IPv4DefaultGateway = if ($_.IPv4DefaultGateway) { $_.IPv4DefaultGateway.NextHop } else { $null }
            MacAddress = $_.NetAdapter.MacAddress
            Status = $_.NetAdapter.Status
        }
    }
$items | ConvertTo-Json -Depth 4
""".strip()
    arp_command: tuple[str, ...] = ("arp", "-a")
    ping_command_template: tuple[str, ...] = ("ping", "-n", "{count}", "-w", "{timeout_ms}", "{ip}")
    reverse_dns_enabled: bool = True
    ping_name_resolution_enabled: bool = True
    ping_name_command_template: tuple[str, ...] = ("ping", "-a", "-n", "1", "-w", "{timeout_ms}", "{ip}")
    netbios_name_resolution_enabled: bool = True
    netbios_command_template: tuple[str, ...] = ("nbtstat", "-A", "{ip}")
    http_title_probe_enabled: bool = True
    http_title_probe_timeout_seconds: float = 1.5
    http_title_probe_urls: tuple[str, ...] = ("http://{ip}/",)
    router_name_resolution_enabled: bool = field(
        default_factory=lambda: _get_bool_env("NETWORK_SCANNER_ROUTER_NAME_RESOLUTION_ENABLED", True)
    )
    router_name_resolution_timeout_seconds: float = 3.0
    router_username: str = field(default_factory=lambda: _get_str_env("NETWORK_SCANNER_ROUTER_USERNAME"))
    router_password: str = field(default_factory=lambda: _get_str_env("NETWORK_SCANNER_ROUTER_PASSWORD"))
    router_query_paths: tuple[str, ...] = ("/",)
    ui_text: UiText = field(default_factory=UiText)
    ui_theme: UiTheme = field(default_factory=UiTheme)


_SETTINGS = AppSettings()


def get_settings() -> AppSettings:
    return _SETTINGS
