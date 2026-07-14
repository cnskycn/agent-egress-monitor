"""测试内容检测 Tab：启动面板后注入假蜜罐/指纹命中数据，验证面板显示。

用法：
  python test_content_tab.py
  然后浏览器打开 http://127.0.0.1:9876 → 切换到「内容检测」Tab

会看到一条带「蜜罐!」红色标记的请求体记录。
"""
import sys, os, threading, time
sys.path.insert(0, os.path.dirname(__file__))

from core import canary, dashboard

# 加载蜜罐和指纹
c = canary.load_canary(".")
token = c["token"] if c else None
fp = canary.load_fingerprints(".")
fp_hash = fp["hashes"][0] if fp and fp["hashes"] else None

if not token:
    print("请先运行 python cli/main.py canary gen --repo .")
    sys.exit(1)

print(f"蜜罐令牌: {token[:20]}...")
if fp_hash:
    print(f"指纹样本: {fp_hash}")

# 启动面板
srv = dashboard.DashboardServer(port=9876, auto_open=True)
srv.start()

# 注入数据必须在 serve() 前（Handler 启动时捕获 state 引用）
srv.state.record_body(
    method="POST",
    host="backend.appmiaoda.com",
    url="https://backend.appmiaoda.com/api/v1/chat/completions",
    body='{"model":"gpt-4","messages":[{"content":"' + token + '"}]}',
    canary_hit=True, fp_hit=False,
)
print("已注入蜜罐命中数据")

if fp_hash:
    srv.state.record_body(
        method="POST",
        host="api.x.ai",
        url="https://api.x.ai/v1/repo/upload",
        body='{"files":["main.py"],"sha256":"' + fp_hash + '"}',
        canary_hit=False, fp_hit=True,
    )
    print("已注入指纹命中数据")

thr = threading.Thread(target=srv.serve, daemon=True)
thr.start()
time.sleep(2)

print(f"\n面板: http://127.0.0.1:9876  → 切换到「内容检测」Tab")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    srv.stop()
