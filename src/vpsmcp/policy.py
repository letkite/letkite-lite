"""Command guardrails.

These catch accidents, not attacks: any string-based filter can be bypassed with
base64 or variable splicing. The real boundary is the SSH user's privileges.
"""
from __future__ import annotations

import re

from .inventory import Host


class PolicyError(PermissionError):
    pass


# Refused outright: almost never intentional, and irreversible.
DENY = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*f?[a-zA-Z]*\s+/(\s|$)"), "rm -rf /"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "format filesystem"),
    (re.compile(r"\bdd\b[^|;&]*\bof=/dev/(sd|nvme|vd|xvd)"), "dd to raw disk"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\b(shred|wipefs)\b[^|;&]*/dev/"), "wipe block device"),
    (re.compile(r">\s*/dev/(sd|nvme|vd|xvd)[a-z0-9]*\s*$"), "overwrite raw disk"),
]

# Allowed but require confirm=true.
CONFIRM = [
    (re.compile(r"\b(reboot|shutdown|halt|poweroff)\b"), "reboot/shutdown"),
    (re.compile(r"\bsystemctl\s+(stop|disable|mask)\b"), "stop systemd service"),
    (re.compile(r"\b(iptables|nft|ufw)\b.*\b(-F|flush|reset)\b"), "flush firewall rules"),
    (re.compile(r"\buserdel\b|\bpasswd\b\s+\w+"), "modify accounts"),
    (re.compile(r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR]"), "recursive delete"),
    (re.compile(r"\b(apt-get|apt|yum|dnf|apk)\b.*\b(remove|purge|autoremove)\b"), "remove packages"),
    (re.compile(r"\bdrop\s+(database|table)\b", re.I), "drop database/table"),
    (re.compile(r"\bgit\b.*\bpush\b.*(--force|-f)\b"), "force push"),
    (re.compile(r"\bchmod\s+(-R\s+)?777\b"), "chmod 777"),
]


def check_command(command: str, *, confirm: bool, enabled: bool = True) -> list[str]:
    """Return warnings. Raise PolicyError on DENY or unconfirmed CONFIRM."""
    if not enabled:
        return []
    flat = " ".join(command.split())
    for rx, why in DENY:
        if rx.search(flat):
            raise PolicyError(f"refused by guardrail ({why}); run it by hand on the host")
    warnings: list[str] = []
    for rx, why in CONFIRM:
        if rx.search(flat):
            if not confirm:
                raise PolicyError(
                    f"high-risk operation ({why}); tell the user the exact command, "
                    f"then call again with confirm=true")
            warnings.append(why)
    return warnings


def require_scope(token_scopes: set[str], needed: str) -> None:
    if needed not in token_scopes and "fleet.admin" not in token_scopes:
        raise PolicyError(f"token lacks {needed} (has: {sorted(token_scopes) or 'none'})")


def require_host_scope(host: Host, needed: str) -> None:
    if not host.allows(needed) and not host.allows("fleet.admin"):
        raise PolicyError(
            f"host {host.alias} does not grant {needed} (grants: {', '.join(host.scopes)})")


def guard(token_scopes: set[str], host: Host, needed: str) -> None:
    require_scope(token_scopes, needed)
    require_host_scope(host, needed)
