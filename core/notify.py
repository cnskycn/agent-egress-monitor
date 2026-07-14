"""告警通知：原生 Windows 弹窗 + SMTP 邮件。

CRITICAL 级别（蜜罐令牌/仓库指纹命中）→ Windows MessageBox 弹窗
WARN 级别（超阈值上传）→ 浏览器 Notification（dashboard.html 已实现）
可选 SMTP 邮件 → 所有告警级别
"""
from __future__ import annotations

import json
import os as _os
import smtplib
import threading
from email.mime.text import MIMEText


def notify_windows(title: str, message: str) -> None:
    """Windows MessageBox 弹窗（仅 CRITICAL 级别使用）。"""
    if _os.name != "nt":
        return
    def _show():
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)  # MB_ICONWARNING | MB_OK
    threading.Thread(target=_show, daemon=True).start()


class EmailNotifier:
    """SMTP 邮件告警（可选）。"""
    def __init__(self, smtp_host: str, smtp_port: int, user: str, password: str,
                 to: str, from_addr: str):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.user = user
        self.password = password
        self.to = to
        self.from_addr = from_addr

    def send(self, subject: str, body: str) -> None:
        def _send():
            try:
                msg = MIMEText(body, "plain", "utf-8")
                msg["Subject"] = subject
                msg["From"] = self.from_addr
                msg["To"] = self.to
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10) as s:
                    s.login(self.user, self.password)
                    s.sendmail(self.from_addr, [self.to], msg.as_string())
            except Exception:
                pass  # 邮件发送失败不阻塞主流程
        threading.Thread(target=_send, daemon=True).start()
