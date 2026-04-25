from __future__ import annotations

import html
import sys
import uuid
from pathlib import Path

from PyQt5.QtCore import Qt, QThreadPool
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from network_scanner.application.scan_controller import ScanController
from network_scanner.config import AppSettings, UiText, get_settings
from network_scanner.domain.models import AdapterInfo, PublicIpInfo, ScanProgress, ScanSummary
from network_scanner.infrastructure import (
    SocketDnsResolver,
    UrlLibPublicIpClient,
    WindowsAdapterProvider,
    WindowsArpReader,
    WindowsPingRunner,
)
from network_scanner.infrastructure.logging_utils import configure_logging
from network_scanner.ui.table_models import DeviceTableModel, IpTableModel
from network_scanner.ui.worker_signals import BackgroundTask


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.settings: AppSettings = get_settings()
        self.texts: UiText = self.settings.ui_text
        self.logger = configure_logging()
        self.thread_pool = QThreadPool.globalInstance()
        self.controller = ScanController(
            settings=self.settings,
            adapter_provider=WindowsAdapterProvider(self.settings),
            public_ip_client=UrlLibPublicIpClient(self.settings),
            ping_runner=WindowsPingRunner(self.settings),
            arp_reader=WindowsArpReader(self.settings),
            dns_resolver=SocketDnsResolver(self.settings),
        )
        self.adapters: list[AdapterInfo] = []
        self.active_tasks: list[BackgroundTask] = []
        self.current_scan_session: str = ""
        self.current_adapter_id: str = ""
        self.is_closing = False

        self.device_model = DeviceTableModel()
        self.free_ip_model = IpTableModel()
        self.info_labels: dict[str, QLabel] = {}
        self.stat_values: dict[str, QLabel] = {}
        self.stat_hints: dict[str, QLabel] = {}

        self.setWindowTitle(self.texts.window_title)
        self.resize(self.settings.ui_theme.window_width, self.settings.ui_theme.window_height)
        self.setStyleSheet(self.settings.ui_theme.stylesheet)
        self._build_ui()
        self._load_initial_state()

    def _build_ui(self) -> None:
        theme = self.settings.ui_theme

        root = QWidget(self)
        root.setObjectName("AppRoot")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(theme.app_margin, theme.app_margin, theme.app_margin, theme.app_margin)
        root_layout.setSpacing(theme.app_spacing)

        header = self._build_header_card()
        header.setMaximumHeight(theme.header_maximum_height)
        root_layout.addWidget(header)

        control_panel = self._build_control_panel()
        root_layout.addWidget(control_panel)

        root_layout.addLayout(self._build_stat_cards())

        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.setChildrenCollapsible(False)
        content_splitter.addWidget(self._build_results_panel())
        content_splitter.addWidget(self._build_sidebar_panel())
        content_splitter.setStretchFactor(0, 5)
        content_splitter.setStretchFactor(1, 2)
        content_splitter.setSizes(
            [
                theme.splitter_left_initial,
                theme.splitter_right_initial,
            ]
        )
        root_layout.addWidget(content_splitter, 1)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar(self))

    def _build_header_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("HeaderCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        text_row = QHBoxLayout()
        text_row.setSpacing(12)

        badge = QLabel(self.texts.hero_badge)
        badge.setObjectName("HeroBadge")
        badge.setAlignment(Qt.AlignCenter)
        badge.setMaximumWidth(140)

        title = QLabel(self.texts.hero_title)
        title.setObjectName("HeroTitle")

        subtitle = QLabel(self.texts.hero_subtitle)
        subtitle.setObjectName("HeroSubtitle")
        subtitle.setWordWrap(True)

        title_column = QVBoxLayout()
        title_column.setSpacing(2)
        title_column.addWidget(title)
        title_column.addWidget(subtitle)

        text_row.addWidget(badge, 0, Qt.AlignTop)
        text_row.addLayout(title_column, 1)
        layout.addLayout(text_row, 1)
        return card

    def _build_control_panel(self) -> QFrame:
        card, body = self._create_panel(self.texts.control_panel_title, self.texts.control_panel_subtitle)
        theme = self.settings.ui_theme

        top_row = QHBoxLayout()
        top_row.setSpacing(theme.section_spacing)
        adapter_label = QLabel(self.texts.adapter_label)
        adapter_label.setObjectName("FieldLabel")
        adapter_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        adapter_label.setFixedHeight(theme.control_row_height)
        self.adapter_combo = QComboBox()
        self.adapter_combo.currentIndexChanged.connect(self._on_adapter_changed)
        self.adapter_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.adapter_combo.setMinimumContentsLength(theme.adapter_combo_minimum_contents_length)
        self.adapter_combo.setFixedHeight(theme.control_row_height)
        self.adapter_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.scan_button = QPushButton(self.texts.scan_button)
        self.scan_button.setObjectName("PrimaryButton")
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setMinimumWidth(theme.control_button_min_width)
        self.scan_button.setFixedHeight(theme.control_row_height)
        self.scan_button.setCursor(Qt.PointingHandCursor)

        self.refresh_adapters_button = QPushButton(self.texts.refresh_adapters_button)
        self.refresh_adapters_button.clicked.connect(self.refresh_adapters)
        self.refresh_adapters_button.setMinimumWidth(theme.control_button_min_width)
        self.refresh_adapters_button.setFixedHeight(theme.control_row_height)
        self.refresh_adapters_button.setCursor(Qt.PointingHandCursor)

        self.refresh_public_ip_button = QPushButton(self.texts.refresh_public_ip_button)
        self.refresh_public_ip_button.clicked.connect(self.refresh_public_ip)
        self.refresh_public_ip_button.setMinimumWidth(theme.control_button_min_width)
        self.refresh_public_ip_button.setFixedHeight(theme.control_row_height)
        self.refresh_public_ip_button.setCursor(Qt.PointingHandCursor)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)

        progress_header = QLabel(self.texts.progress_panel_title)
        progress_header.setObjectName("FieldLabel")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.progress_label = QLabel(self.texts.ready_status)
        self.progress_label.setObjectName("MutedText")
        self.progress_label.setWordWrap(True)

        top_row.addWidget(adapter_label)
        top_row.addWidget(self.adapter_combo, 1)
        top_row.addWidget(self.refresh_adapters_button)
        top_row.addWidget(self.refresh_public_ip_button)
        top_row.addWidget(self.scan_button)

        progress_row.addWidget(progress_header)
        progress_row.addWidget(self.progress_bar, 1)
        progress_row.addWidget(self.progress_label, 2)

        body.addLayout(top_row)
        body.addLayout(progress_row)
        return card

    def _build_stat_cards(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.setSpacing(self.settings.ui_theme.section_spacing)

        adapter_card = self._create_stat_card(
            self.texts.stat_adapter_label,
            self.texts.public_ip_unavailable,
            self.texts.card_hint_scan,
        )
        self.stat_values["adapter"] = adapter_card.findChild(QLabel, "StatValue")
        self.stat_hints["adapter"] = adapter_card.findChild(QLabel, "StatHint")

        public_ip_card = self._create_stat_card(
            self.texts.stat_public_ip_label,
            self.texts.public_ip_unavailable,
            self.texts.card_hint_public_ip,
        )
        self.stat_values["public_ip"] = public_ip_card.findChild(QLabel, "StatValue")
        self.stat_hints["public_ip"] = public_ip_card.findChild(QLabel, "StatHint")

        device_card = self._create_stat_card(
            self.texts.stat_device_count_label,
            "0",
            self.texts.ready_status,
        )
        self.stat_values["devices"] = device_card.findChild(QLabel, "StatValue")
        self.stat_hints["devices"] = device_card.findChild(QLabel, "StatHint")

        free_ip_card = self._create_stat_card(
            self.texts.stat_free_ip_count_label,
            "0",
            self.texts.card_hint_scan,
        )
        self.stat_values["free_ips"] = free_ip_card.findChild(QLabel, "StatValue")
        self.stat_hints["free_ips"] = free_ip_card.findChild(QLabel, "StatHint")

        layout.addWidget(adapter_card)
        layout.addWidget(public_ip_card)
        layout.addWidget(device_card)
        layout.addWidget(free_ip_card)
        return layout

    def _build_results_panel(self) -> QFrame:
        card, body = self._create_panel(self.texts.results_panel_title, self.texts.results_panel_subtitle)
        card.setMinimumHeight(self.settings.ui_theme.results_panel_minimum_height)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        tabs = QTabWidget()
        tabs.setDocumentMode(False)
        tabs.tabBar().setCursor(Qt.PointingHandCursor)
        tabs.tabBar().setDrawBase(False)

        self.device_table = QTableView()
        self.device_table.setModel(self.device_model)
        self._configure_table(self.device_table)
        tabs.addTab(self.device_table, self.texts.devices_tab_title)

        self.free_ip_table = QTableView()
        self.free_ip_table.setModel(self.free_ip_model)
        self._configure_table(self.free_ip_table)
        tabs.addTab(self.free_ip_table, self.texts.free_ips_tab_title)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setHtml(self._empty_summary_html())
        tabs.addTab(self.summary_text, self.texts.summary_tab_title)

        body.addWidget(tabs, 1)
        return card

    def _build_sidebar_panel(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(self.settings.ui_theme.section_spacing)
        layout.addWidget(self._build_info_panel())
        return container

    def _build_info_panel(self) -> QFrame:
        card, body = self._create_panel(self.texts.info_panel_title, self.texts.info_panel_subtitle)
        card.setMinimumWidth(self.settings.ui_theme.info_panel_minimum_width)
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(8)

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(8)
        info_fields = (
            ("adapter", self.texts.info_field_adapter),
            ("ipv4", self.texts.info_field_ipv4),
            ("subnet", self.texts.info_field_subnet),
            ("cidr", self.texts.info_field_cidr),
            ("network", self.texts.info_field_network),
            ("broadcast", self.texts.info_field_broadcast),
            ("gateway", self.texts.info_field_gateway),
            ("public_ip", self.texts.info_field_public_ip),
            ("public_status", self.texts.info_field_public_status),
        )
        for row, (key, label_text) in enumerate(info_fields):
            label = QLabel(label_text)
            label.setObjectName("FieldLabel")
            value = QLabel(self.texts.table_placeholder_value)
            value.setObjectName("FieldValue")
            value.setWordWrap(True)
            grid.addWidget(label, row, 0)
            grid.addWidget(value, row, 1)
            self.info_labels[key] = value

        content_layout.addLayout(grid)
        content_layout.addStretch(1)

        scroll.setWidget(content)
        body.addWidget(scroll, 1)
        return card

    def _create_panel(self, title_text: str, subtitle_text: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("PanelCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(8)

        title = QLabel(title_text)
        title.setObjectName("PanelTitle")

        subtitle = QLabel(subtitle_text)
        subtitle.setObjectName("PanelSubtitle")
        subtitle.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        return card, layout

    def _create_stat_card(self, title_text: str, value_text: str, hint_text: str) -> QFrame:
        card = QFrame()
        card.setObjectName("StatCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        title = QLabel(title_text)
        title.setObjectName("StatLabel")

        value = QLabel(value_text)
        value.setObjectName("StatValue")
        value.setWordWrap(True)

        hint = QLabel(hint_text)
        hint.setObjectName("StatHint")
        hint.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(value)
        layout.addWidget(hint)
        return card

    def _configure_table(self, table: QTableView) -> None:
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setHighlightSections(False)

    def _load_initial_state(self) -> None:
        self.refresh_adapters()
        self.refresh_public_ip()

    def refresh_adapters(self) -> None:
        self.statusBar().showMessage(self.texts.adapter_loading_status)
        self.progress_label.setText(self.texts.adapter_loading_status)
        try:
            adapters, default_adapter = self.controller.load_adapters()
        except Exception as exc:
            self._show_error(f"{self.texts.adapter_load_error_prefix}: {exc}")
            self.adapters = []
            self.adapter_combo.clear()
            self.scan_button.setEnabled(False)
            return

        self.adapters = adapters
        self.adapter_combo.blockSignals(True)
        self.adapter_combo.clear()
        for adapter in adapters:
            label = f"{adapter.interface_alias} • {adapter.ipv4_address}/{adapter.prefix_length}"
            self.adapter_combo.addItem(label, adapter.adapter_id)
        self.adapter_combo.blockSignals(False)

        if not adapters:
            self._clear_adapter_info()
            self._update_stat("adapter", self.texts.public_ip_unavailable, self.texts.adapter_not_found_status)
            self.scan_button.setEnabled(False)
            self.progress_label.setText(self.texts.adapter_not_found_status)
            self.statusBar().showMessage(self.texts.adapter_not_found_status)
            return

        self.scan_button.setEnabled(True)
        target_adapter = default_adapter or adapters[0]
        target_index = next(
            (index for index, adapter in enumerate(adapters) if adapter.adapter_id == target_adapter.adapter_id),
            0,
        )
        self.adapter_combo.setCurrentIndex(target_index)
        self._apply_adapter(adapters[target_index])
        self.statusBar().showMessage(self.texts.adapter_loaded_status)
        self.progress_label.setText(self.texts.ready_status)

    def refresh_public_ip(self) -> None:
        self.info_labels["public_status"].setText(self.texts.public_ip_loading_status)
        self._update_stat("public_ip", self.texts.public_ip_loading_status, self.texts.card_hint_public_ip)
        worker = BackgroundTask(self.controller.fetch_public_ip)
        worker.signals.result.connect(self._apply_public_ip)
        worker.signals.error.connect(self._show_error)
        self._start_task(worker)

    def start_scan(self) -> None:
        adapter = self._selected_adapter()
        if not adapter:
            self._show_error(self.texts.invalid_adapter_error)
            return

        self.current_scan_session = uuid.uuid4().hex
        self.current_adapter_id = adapter.adapter_id
        self._set_scan_controls_enabled(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText(self.texts.scan_starting_status)
        self.summary_text.setHtml(self._empty_summary_html())
        self._update_stat("devices", "0", self.texts.scan_starting_status)
        self._update_stat("free_ips", "0", self.texts.card_hint_scan)

        worker = BackgroundTask(
            self.controller.scan_network,
            adapter,
            self.current_scan_session,
        )
        worker.signals.progress.connect(self._handle_scan_progress)
        worker.signals.result.connect(self._handle_scan_result)
        worker.signals.error.connect(self._show_error)
        worker.signals.finished.connect(lambda: self._set_scan_controls_enabled(True))
        self._start_task(worker)

    def _handle_scan_progress(self, progress: object) -> None:
        if self.is_closing:
            return
        if not isinstance(progress, ScanProgress):
            return
        percentage = 0 if progress.total == 0 else int((progress.current / progress.total) * 100)
        self.progress_bar.setValue(max(0, min(100, percentage)))
        self.progress_label.setText(progress.message)

    def _handle_scan_result(self, summary: object) -> None:
        if self.is_closing:
            return
        if not isinstance(summary, ScanSummary):
            return
        if summary.session_id != self.current_scan_session:
            return
        self.device_model.update_data(summary.devices)
        self.free_ip_model.update_data(summary.free_ips)
        self.progress_bar.setValue(100)
        self.progress_label.setText(summary.status_message)
        self.summary_text.setHtml(self._format_summary_html(summary))
        self.statusBar().showMessage(summary.status_message)
        self._update_stat("devices", str(len(summary.devices)), summary.status_message)
        self._update_stat("free_ips", str(len(summary.free_ips)), summary.warning_message or self.texts.card_hint_scan)

    def _apply_public_ip(self, public_ip: object) -> None:
        if self.is_closing:
            return
        if not isinstance(public_ip, PublicIpInfo):
            return
        ip_value = public_ip.ip or self.texts.public_ip_unavailable
        status_value = public_ip.status_message or self.texts.public_ip_unavailable
        self.info_labels["public_ip"].setText(ip_value)
        self.info_labels["public_status"].setText(status_value)
        self._update_stat("public_ip", ip_value, status_value)

    def _selected_adapter(self) -> AdapterInfo | None:
        index = self.adapter_combo.currentIndex()
        if index < 0 or index >= len(self.adapters):
            return None
        return self.adapters[index]

    def _on_adapter_changed(self, index: int) -> None:
        if index < 0 or index >= len(self.adapters):
            self._clear_adapter_info()
            return
        self._apply_adapter(self.adapters[index])

    def _apply_adapter(self, adapter: AdapterInfo) -> None:
        self.info_labels["adapter"].setText(adapter.interface_alias)
        self.info_labels["ipv4"].setText(adapter.ipv4_address)
        self.info_labels["subnet"].setText(adapter.subnet_mask)
        self.info_labels["cidr"].setText(adapter.cidr)
        self.info_labels["network"].setText(adapter.network_address)
        self.info_labels["broadcast"].setText(adapter.broadcast_address)
        self.info_labels["gateway"].setText(adapter.gateway or self.texts.table_placeholder_value)
        self._update_stat("adapter", adapter.interface_alias, adapter.ipv4_address)

    def _clear_adapter_info(self) -> None:
        for label in self.info_labels.values():
            label.setText(self.texts.table_placeholder_value)

    def _update_stat(self, key: str, value: str, hint: str) -> None:
        if key in self.stat_values:
            self.stat_values[key].setText(value)
        if key in self.stat_hints:
            self.stat_hints[key].setText(hint)

    def _set_scan_controls_enabled(self, enabled: bool) -> None:
        self.scan_button.setEnabled(enabled and bool(self.adapters))
        self.adapter_combo.setEnabled(enabled and bool(self.adapters))
        self.refresh_adapters_button.setEnabled(enabled)
        self.refresh_public_ip_button.setEnabled(enabled)

    def _empty_summary_html(self) -> str:
        return (
            f"<h3>{html.escape(self.texts.summary_empty_title)}</h3>"
            f"<p>{html.escape(self.texts.summary_empty_body)}</p>"
        )

    def _format_summary_html(self, summary: ScanSummary) -> str:
        started = summary.started_at.strftime("%Y-%m-%d %H:%M:%S") if summary.started_at else self.texts.table_placeholder_value
        completed = (
            summary.completed_at.strftime("%Y-%m-%d %H:%M:%S")
            if summary.completed_at
            else self.texts.table_placeholder_value
        )
        lines = [
            (self.texts.summary_label_adapter, summary.adapter.interface_alias),
            (self.texts.summary_label_local_ipv4, summary.adapter.cidr),
            (self.texts.summary_label_gateway, summary.adapter.gateway or self.texts.table_placeholder_value),
            (self.texts.summary_label_started_at, started),
            (self.texts.summary_label_completed_at, completed),
            (self.texts.summary_label_total_hosts, str(summary.total_hosts)),
            (self.texts.summary_label_device_count, str(len(summary.devices))),
            (self.texts.summary_label_free_ip_count, str(len(summary.free_ips))),
            (self.texts.summary_label_excluded_ips, ", ".join(summary.excluded_ips) or self.texts.table_placeholder_value),
            (self.texts.summary_label_status, summary.status_message),
        ]
        if summary.warning_message:
            lines.append((self.texts.summary_label_warning, summary.warning_message))

        rendered_rows = "".join(
            f"<p><b>{html.escape(label)}:</b> {html.escape(value)}</p>" for label, value in lines
        )
        return f"<h3>{html.escape(self.texts.summary_panel_title)}</h3>{rendered_rows}"

    def _show_error(self, message: str) -> None:
        if self.is_closing:
            return
        self.statusBar().showMessage(self.texts.generic_error_status)
        self.progress_label.setText(self.texts.generic_error_status)
        QMessageBox.warning(self, self.texts.error_dialog_title, message)

    def _start_task(self, worker: BackgroundTask) -> None:
        self.active_tasks.append(worker)
        worker.signals.finished.connect(lambda task=worker: self._release_task(task))
        self.thread_pool.start(worker)

    def _release_task(self, worker: BackgroundTask) -> None:
        if worker in self.active_tasks:
            self.active_tasks.remove(worker)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.is_closing = True
        self.thread_pool.waitForDone(2000)
        super().closeEvent(event)


def _ensure_repo_src_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    src_path = repo_root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))


def run() -> int:
    _ensure_repo_src_on_path()
    app = QApplication(sys.argv)
    theme = get_settings().ui_theme
    app.setFont(QFont(theme.body_font_family, theme.body_font_size))
    window = MainWindow()
    window.show()
    return app.exec_()
