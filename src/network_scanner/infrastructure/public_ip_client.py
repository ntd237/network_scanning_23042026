from __future__ import annotations

import json
from urllib import error, request

from network_scanner.config import AppSettings
from network_scanner.domain.models import PublicIpInfo


class UrlLibPublicIpClient:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def fetch(self) -> PublicIpInfo:
        req = request.Request(
            self.settings.public_ip_url,
            headers={"User-Agent": "network-scanner/0.1"},
        )
        try:
            with request.urlopen(req, timeout=self.settings.public_ip_timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (error.URLError, OSError, TimeoutError):
            return PublicIpInfo(status_message="Không thể lấy public IP.", success=False)
        except json.JSONDecodeError:
            return PublicIpInfo(status_message="Dữ liệu public IP không hợp lệ.", success=False)

        ip_value = payload.get("ip", "")
        if not ip_value:
            return PublicIpInfo(status_message="Endpoint không trả về trường IP.", success=False)
        return PublicIpInfo(
            ip=ip_value,
            provider="ipify",
            status_message="Đã cập nhật public IP.",
            success=True,
        )
