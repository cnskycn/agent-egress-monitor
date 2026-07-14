"""规则引擎。

将抓包/解密得到的事件与蜜罐、指纹、体积、域名策略比对，产出告警。
"""
from __future__ import annotations

from dataclasses import dataclass

from core.event import EgressEvent

# ============================================================
# 已知 AI 编码代理 / 大模型 API / 云存储域名
# 在 Web 面板中自动 [AGENT] 高亮，在规则引擎中触发体积阈值减半
# ============================================================

# --- 国际 AI 编码代理 ---
_AGENTS_INTL = [
    "githubcopilot.com",       # GitHub Copilot
    "copilot.github.com",
    "cursor.com",              # Cursor
    "cursor.sh",               # Cursor API
    "codeium.com",             # Windsurf / Codeium
    "sourcegraph.com",         # Sourcegraph Cody
    "aider.chat",              # Aider
    "continue.dev",            # Continue
    "cline.dev",               # Cline
    "tabnine.com",             # Tabnine
    "replit.com",              # Replit AI
    "amazonaws.com",           # Amazon Q / CodeWhisperer (via Bedrock)
]

# --- 国际大模型 API 后端 ---
_APIS_INTL = [
    "anthropic.com",           # Claude API
    "openai.com",              # ChatGPT / GPT-4 API
    "x.ai",                    # Grok
    "googleapis.com",          # Gemini
    "api.mistral.ai",          # Mistral
    "cohere.ai",               # Cohere
    "deepinfra.com",           # DeepInfra (开源模型托管)
    "together.xyz",            # Together AI
    "groq.com",                # Groq
    "fireworks.ai",            # Fireworks AI
    "perplexity.ai",           # Perplexity
    "deepseek.com",            # DeepSeek (国际用户也用)
]

# --- 国内 AI 编码代理 ---
_AGENTS_CN = [
    "tongyi.aliyun.com",       # 通义灵码
    "lingma.aliyun.com",       # 通义灵码
    "devops.aliyun.com",       # 阿里云 DevOps
    "comate.baidu.com",        # 百度 Comate
    "marscode.com",            # 字节豆包 MarsCode
    "marscode.cn",
    "bytedance.com",           # 字节系
    "codegeex.cn",             # 智谱 CodeGeeX
    "bigmodel.cn",             # 智谱 API
    "zhipuai.cn",              # 智谱
    "iflycode.com",            # 讯飞 iFlyCode
    "xfyun.cn",                # 讯飞
    "iflytek.com",
]

# --- 国内大模型 API 后端 ---
_APIS_CN = [
    "dashscope.aliyuncs.com",  # 阿里通义千问 API
    "qianwen.aliyun.com",      # 通义千问
    "qianfan.baidubce.com",    # 百度千帆
    "aip.baidubce.com",        # 百度 AI
    "volcengineapi.com",       # 火山引擎 (豆包 API)
    "ark.cn-beijing.volces.com",  # 火山方舟
    "open.bigmodel.cn",        # 智谱开放平台
    "deepseek.com",            # DeepSeek
    "api-d.deepseek.com",      # DeepSeek API
    "siliconflow.cn",          # 硅基流动
    "infini.ai",               # 无问芯穹
    "moonshot.cn",             # 月之暗面 Kimi
    "kimi.moonshot.cn",
    "minimax.io",              # MiniMax
    "minimaxi.com",
    "01.ai",                   # 零一万物
    "lingyiwanwu.com",
    "baichuan-ai.com",         # 百川
    "stepfun.com",             # 阶跃星辰
    "z.ai",                    # 智谱
]

# --- 云存储 / CDN（代码可能被上传到这里）---
_CLOUD_STORAGE = [
    "myqcloud.com",            # 腾讯云 COS
    "aliyuncs.com",            # 阿里云 OSS
    "blob.core.windows.net",   # Azure Blob
    "amazonaws.com",           # AWS S3
    "storage.googleapis.com",  # GCP Cloud Storage
    "r2.cloudflarestorage.com",# Cloudflare R2
    "bcebos.com",              # 百度 BOS
    "obs.cn-",                 # 华为云 OBS
    "qiniucs.com",             # 七牛
    "upyun.com",               # 又拍云
]

# --- WorkBuddy 自身后端（真机抓包实测确认）---
_WORKBUDDY = [
    "copilot.tencent.com",
    "appmiaoda.com",
    "tgalileo.com",
    "galileotelemetry",
    "myqcloud.com",            # 复用 COS
    "agnes-ai.com",            # Agnes AI
]

# 合并
KNOWN_AGENT_DOMAINS = tuple(dict.fromkeys(
    _AGENTS_INTL + _APIS_INTL + _AGENTS_CN + _APIS_CN + _CLOUD_STORAGE + _WORKBUDDY
))

# 厂商云域名：上行超过阈值一半时就触发 high 告警
VENDOR_CLOUD = tuple(dict.fromkeys(
    _APIS_INTL + _APIS_CN + _CLOUD_STORAGE
))


def is_known_agent_domain(domain: str) -> bool:
    d = (domain or "").lower()
    return any(k in d for k in KNOWN_AGENT_DOMAINS)


# 域名 → 工具名（面板"域名画像"Tab 自动标注归属）
_DOMAIN_TOOL = {
    "githubcopilot.com": "GitHub Copilot", "copilot.github.com": "GitHub Copilot",
    "cursor.com": "Cursor", "cursor.sh": "Cursor",
    "codeium.com": "Windsurf", "sourcegraph.com": "Sourcegraph Cody",
    "aider.chat": "Aider", "continue.dev": "Continue", "cline.dev": "Cline",
    "tabnine.com": "Tabnine", "replit.com": "Replit", "amazonaws.com": "Amazon Q",
    "tongyi.aliyun.com": "通义灵码", "lingma.aliyun.com": "通义灵码",
    "comate.baidu.com": "百度 Comate",
    "marscode.com": "MarsCode", "marscode.cn": "MarsCode",
    "codegeex.cn": "CodeGeeX", "bigmodel.cn": "智谱", "zhipuai.cn": "智谱",
    "iflycode.com": "iFlyCode", "xfyun.cn": "讯飞",
    "deepseek.com": "DeepSeek", "moonshot.cn": "Kimi",
    "minimax.io": "MiniMax", "01.ai": "零一万物", "baichuan-ai.com": "百川",
    "copilot.tencent.com": "WorkBuddy", "appmiaoda.com": "WorkBuddy",
    "tgalileo.com": "WorkBuddy", "galileotelemetry": "WorkBuddy",
    "myqcloud.com": "腾讯COS", "aliyuncs.com": "阿里OSS",
    "volcengineapi.com": "豆包/火山", "bytedance.com": "豆包/火山",
    "openai.com": "ChatGPT", "anthropic.com": "Claude API",
    "x.ai": "Grok", "googleapis.com": "Gemini",
}
_AGENT_PROCS = {
    "WorkBuddy.exe": "WorkBuddy", "Trae.exe": "Trae", "Trae CN.exe": "Trae",
    "Qoder.exe": "Qoder", "Cursor.exe": "Cursor", "Windsurf.exe": "Windsurf",
    "Code.exe": "VS Code", "claude": "Claude CLI", "grok": "Grok CLI",
    "codebuddy": "CodeBuddy CLI",
}


def get_tool_for_domain(domain: str) -> str:
    d = (domain or "").lower()
    for pattern, tool in _DOMAIN_TOOL.items():
        if pattern in d:
            return tool
    return ""


def detect_running_agents() -> list[tuple[str, str]]:
    """扫描当前运行的 Agent 进程。"""
    try:
        import psutil
        found, seen = [], set()
        for p in psutil.process_iter(["name"]):
            try:
                name = p.info["name"] or ""
            except Exception:
                continue
            if name in _AGENT_PROCS and name not in seen:
                seen.add(name)
                found.append((name, _AGENT_PROCS[name]))
        return found
    except Exception:
        return []


@dataclass
class Config:
    size_threshold: int = 1_000_000  # 单连接上行超过即可疑（字节）


def evaluate(event: EgressEvent, cfg: Config) -> list[tuple[str, str]]:
    alerts: list[tuple[str, str]] = []
    domain = event.sni or (event.dst or "")
    if event.uplink_bytes and event.uplink_bytes > cfg.size_threshold:
        alerts.append(("warn", f"大体积上行 {event.uplink_bytes} bytes -> {domain}"))
    if any(v in domain for v in VENDOR_CLOUD) and event.uplink_bytes:
        if event.uplink_bytes > cfg.size_threshold // 2:
            alerts.append(("high", f"向厂商云 {domain} 上行 {event.uplink_bytes} bytes"))
    if event.body_contains_canary:
        alerts.append(("critical", "请求体含蜜罐令牌！确认代码外泄"))
    if event.body_contains_fingerprint:
        alerts.append(("critical", "请求体含仓库指纹！确认代码外泄"))
    return alerts
