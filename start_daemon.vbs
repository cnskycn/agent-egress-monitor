' Agent Egress Monitor — 无窗口后台启动（系统托盘模式）
' 开机自启：将此文件快捷方式放入 shell:startup 文件夹
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """E:\Users\cnskycn\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"" ""E:\cnskycn\Documents\agent-egress-monitor\cli\main.py"" tray --iface WLAN", 0, False
