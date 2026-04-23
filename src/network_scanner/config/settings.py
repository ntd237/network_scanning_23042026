from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UiText:
    window_title: str = "Bảng điều khiển quét mạng"
    hero_badge: str = "Desktop • Windows • PyQt5"
    hero_title: str = "Toàn cảnh mạng nội bộ"
    hero_subtitle: str = (
        "Theo dõi adapter đang hoạt động, cập nhật public IP và quét nhanh các địa chỉ khả dụng "
        "trong mạng LAN từ một màn hình duy nhất."
    )
    control_panel_title: str = "Bộ điều khiển quét"
    control_panel_subtitle: str = "Chọn adapter, cập nhật dữ liệu và khởi chạy phiên quét mới."
    adapter_label: str = "Adapter đang chọn"
    refresh_adapters_button: str = "Làm mới adapter"
    refresh_public_ip_button: str = "Cập nhật public IP"
    scan_button: str = "Quét mạng LAN"
    info_panel_title: str = "Thông tin mạng hiện tại"
    info_panel_subtitle: str = "Chi tiết IPv4, gateway và trạng thái public IP của adapter đang dùng."
    progress_panel_title: str = "Tiến trình quét"
    progress_panel_subtitle: str = "Theo dõi thời gian thực trong lúc ứng dụng quét subnet."
    results_panel_title: str = "Kết quả quét"
    results_panel_subtitle: str = "Danh sách thiết bị phát hiện được và các IP còn khả dụng."
    summary_panel_title: str = "Nhật ký phiên quét"
    summary_panel_subtitle: str = "Tóm tắt nhanh tình trạng mạng sau mỗi phiên quét."
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
    summary_empty_title: str = "Chưa có phiên quét nào"
    summary_empty_body: str = "Chọn adapter rồi nhấn “Quét mạng LAN” để bắt đầu thu thập dữ liệu."
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
    card_hint_public_ip: str = "Tự động lấy từ Internet"
    card_hint_scan: str = "Tối ưu cho mạng IPv4 nội bộ"


@dataclass(frozen=True)
class UiTheme:
    window_width: int = 1380
    window_height: int = 880
    body_font_family: str = "Segoe UI"
    heading_font_family: str = "Bahnschrift"
    body_font_size: int = 10
    heading_font_size: int = 18
    stylesheet: str = """
QWidget#AppRoot {
    background-color: #f4f7fb;
}
QFrame#HeroCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #113c5d, stop:1 #1f6f78);
    border-radius: 28px;
    border: 1px solid rgba(255, 255, 255, 0.12);
}
QFrame#PanelCard, QFrame#StatCard {
    background-color: #ffffff;
    border: 1px solid #dbe4ee;
    border-radius: 22px;
}
QLabel#HeroBadge {
    color: #cfe9ff;
    background-color: rgba(255, 255, 255, 0.12);
    border-radius: 14px;
    padding: 6px 12px;
    font-weight: 600;
}
QLabel#HeroTitle {
    color: #ffffff;
    font-size: 28px;
    font-weight: 700;
}
QLabel#HeroSubtitle {
    color: #d7ebf5;
    font-size: 13px;
}
QLabel#PanelTitle {
    color: #16324f;
    font-size: 18px;
    font-weight: 700;
}
QLabel#PanelSubtitle {
    color: #6b7b8f;
    font-size: 12px;
}
QLabel#FieldLabel {
    color: #5f6f82;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
}
QLabel#FieldValue {
    color: #10263d;
    font-size: 13px;
    font-weight: 600;
}
QLabel#StatLabel {
    color: #688097;
    font-size: 11px;
    font-weight: 600;
}
QLabel#StatValue {
    color: #143e5f;
    font-size: 20px;
    font-weight: 700;
}
QLabel#StatHint {
    color: #8293a6;
    font-size: 11px;
}
QComboBox {
    min-height: 42px;
    border: 1px solid #cfd9e3;
    border-radius: 14px;
    background-color: #ffffff;
    padding: 0 14px;
    color: #16324f;
}
QComboBox::drop-down {
    width: 28px;
    border: none;
}
QPushButton {
    min-height: 42px;
    padding: 0 18px;
    border-radius: 14px;
    border: 1px solid #cfd9e3;
    background-color: #f9fbfd;
    color: #17324e;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #eef4fa;
}
QPushButton#PrimaryButton {
    background-color: #153e5c;
    border-color: #153e5c;
    color: #ffffff;
}
QPushButton#PrimaryButton:hover {
    background-color: #0f314a;
}
QPushButton:disabled {
    background-color: #eef2f6;
    border-color: #d7e0e8;
    color: #97a7b7;
}
QProgressBar {
    min-height: 16px;
    border-radius: 8px;
    border: none;
    background-color: #e5edf4;
    text-align: center;
    color: #143e5f;
}
QProgressBar::chunk {
    border-radius: 8px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2f8f9d, stop:1 #58c4b8);
}
QTabWidget::pane {
    border: 1px solid #dde5ee;
    border-radius: 18px;
    background-color: #ffffff;
    top: -1px;
}
QTabBar::tab {
    min-width: 150px;
    padding: 12px 18px;
    margin-right: 6px;
    border-top-left-radius: 14px;
    border-top-right-radius: 14px;
    background-color: #eaf0f6;
    color: #516579;
    font-weight: 600;
}
QTabBar::tab:selected {
    background-color: #ffffff;
    color: #153e5c;
}
QTableView {
    border: none;
    background-color: #ffffff;
    alternate-background-color: #f6f9fc;
    selection-background-color: #d9ebf8;
    selection-color: #10263d;
    gridline-color: #eef3f7;
    padding: 6px;
}
QHeaderView::section {
    background-color: #f1f6fa;
    color: #546b80;
    border: none;
    border-bottom: 1px solid #dde5ee;
    padding: 12px 10px;
    font-weight: 700;
}
QTextEdit {
    border: 1px solid #dde5ee;
    border-radius: 18px;
    background-color: #fbfdff;
    color: #17324e;
    padding: 8px;
}
QStatusBar {
    background-color: #ffffff;
    border-top: 1px solid #dde5ee;
    color: #52667c;
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
    ui_text: UiText = field(default_factory=UiText)
    ui_theme: UiTheme = field(default_factory=UiTheme)


_SETTINGS = AppSettings()


def get_settings() -> AppSettings:
    return _SETTINGS
