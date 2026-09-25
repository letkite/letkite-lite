"""Client profiles: everything this server has to know about an MCP host.

A profile is a display name plus the `redirect_uri` prefixes that client sends
users back to. Nothing else in the flow differs between clients, so supporting
one more is one row here - or one runtime entry:

    sudo vpsmcp redirect allow https://example.ai/api/mcp/callback

Prefixes are host-scoped on purpose. Claude publishes a fixed callback path;
Kimi and GLM do not document theirs and a vendor may move it without notice, so
a prefix pins the host and leaves the path open. The consequence is explicit:
trusting a host means trusting it not to host an open redirect, which is why the
consent page names the callback host and which client it belongs to before you
approve anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ClientProfile:
    key: str
    name: str
    redirects: tuple[str, ...]
    notes: str = ""

    def matches(self, uri: str) -> bool:
        return any(uri == p or uri.startswith(p) for p in self.redirects)


PROFILES: dict[str, ClientProfile] = {
    "claude": ClientProfile(
        key="claude",
        name="Claude",
        redirects=(
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
        ),
        notes="Settings -> Connectors -> add a custom connector",
    ),
    "local": ClientProfile(
        key="local",
        name="Local clients",
        redirects=(
            "http://localhost/callback",
            "http://127.0.0.1/callback",
        ),
        notes="Claude Code, MCP Inspector: RFC 8252 loopback, any port",
    ),
    "kimi": ClientProfile(
        key="kimi",
        name="Kimi (Moonshot AI)",
        redirects=(
            "https://kimi.com/",
            "https://www.kimi.com/",
            "https://kimi.moonshot.cn/",
            "https://www.kimi.moonshot.cn/",
            "https://platform.moonshot.cn/",
            "https://platform.moonshot.ai/",
        ),
        notes="host-scoped; if the callback lives elsewhere, `vpsmcp redirects` prints it",
    ),
    "glm": ClientProfile(
        key="glm",
        name="GLM (Zhipu AI / Z.ai)",
        redirects=(
            "https://chat.z.ai/",
            "https://z.ai/",
            "https://chatglm.cn/",
            "https://www.chatglm.cn/",
            "https://open.bigmodel.cn/",
            "https://bigmodel.cn/",
        ),
        notes="host-scoped; covers the chat clients and the open platform",
    ),
}

DEFAULT_CLIENTS = ("claude", "local", "kimi", "glm")


def enabled_profiles(keys: tuple[str, ...]) -> list[ClientProfile]:
    """Profiles for the configured keys, in configuration order. Unknown keys are
    skipped: a typo in VPSMCP_CLIENTS must not take the server down."""
    out, seen = [], set()
    for k in keys:
        p = PROFILES.get(k.strip().lower())
        if p and p.key not in seen:
            seen.add(p.key)
            out.append(p)
    return out


def redirects_for(keys: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for p in enabled_profiles(keys):
        out.extend(r for r in p.redirects if r not in out)
    return tuple(out)


def profile_for_redirect(uri: str, keys: tuple[str, ...]) -> ClientProfile | None:
    """Which enabled client a callback belongs to, for the consent page."""
    for p in enabled_profiles(keys):
        if p.matches(uri):
            return p
    return None


def unknown_keys(keys: tuple[str, ...]) -> list[str]:
    return [k for k in keys if k.strip().lower() not in PROFILES]


def guess_client(uri: str) -> str:
    """Best-effort label for a callback nobody recognises: its host."""
    try:
        return urlparse(uri).netloc or "?"
    except ValueError:
        return "?"
