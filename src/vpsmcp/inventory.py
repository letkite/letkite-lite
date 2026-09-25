"""Host inventory.

Identity is node_id (address:port:user); alias is a display label and may repeat.
hosts.yaml is hand-maintained; hosts.d/<node_id>.yaml is written by enrollment.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ALIAS_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


class InventoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Host:
    alias: str
    address: str
    user: str = "root"
    port: int = 22
    key_file: str | None = None      # overrides the global key
    host_key: str | None = None      # pinned host public key
    tags: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ("fleet.read", "fleet.exec", "fleet.write")
    workdir: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    sudo: bool = False
    jump: str | None = None
    notes: str = ""

    @property
    def node_id(self) -> str:
        raw = f"{self.address}:{self.port}:{self.user}".lower()
        return "n_" + hashlib.sha256(raw.encode()).hexdigest()[:10]

    @property
    def label(self) -> str:
        return f"{self.alias} ({self.user}@{self.address})"

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass
class Inventory:
    hosts: dict[str, Host]           # keyed by node_id
    path: Path
    mtime: float

    def get(self, key: str) -> Host:
        """Look up by node_id, or by alias when unambiguous."""
        h = self.hosts.get(key)
        if h is not None:
            return h
        matches = [x for x in self.hosts.values() if x.alias == key]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            opts = "; ".join(f"{m.node_id} = {m.label}" for m in matches)
            raise InventoryError(
                f"alias {key!r} matches {len(matches)} hosts, use a node_id: {opts}")
        avail = ", ".join(sorted({x.alias for x in self.hosts.values()})) or "(none)"
        raise InventoryError(f"unknown host {key!r}; known aliases: {avail}")

    def select(self, *, aliases: list[str] | None = None,
               tags: list[str] | None = None) -> list[Host]:
        if aliases:
            return [self.get(a) for a in aliases]
        if tags:
            want = set(tags)
            out = [h for h in self.hosts.values() if want & set(h.tags)]
            if not out:
                raise InventoryError(f"no host matches tags {tags}")
            return sorted(out, key=lambda h: h.alias)
        raise InventoryError("provide either hosts or tags")


def hosts_d(path: Path) -> Path:
    return path.parent / "hosts.d"


def _sources(path: Path) -> list[Path]:
    out = [path] if path.exists() else []
    d = hosts_d(path)
    if d.is_dir():
        out.extend(sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")))
    return out


def _mtime(path: Path) -> float:
    return max((p.stat().st_mtime for p in _sources(path)), default=0.0)


def _merge(defaults: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    out = dict(defaults)
    out.update({k: v for k, v in item.items() if v is not None})
    env = dict(defaults.get("env") or {})
    env.update(item.get("env") or {})
    out["env"] = env
    return out


def load_inventory(path: Path) -> Inventory:
    if not path.exists():
        raise InventoryError(f"inventory file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults = raw.get("defaults") or {}
    items = list(raw.get("hosts") or [])
    for extra in _sources(path)[1:]:
        sub = yaml.safe_load(extra.read_text(encoding="utf-8")) or {}
        if isinstance(sub, dict) and sub.get("hosts"):
            items.extend(sub["hosts"])
        elif isinstance(sub, dict) and sub.get("alias"):
            items.append(sub)
        elif isinstance(sub, list):
            items.extend(sub)

    hosts: dict[str, Host] = {}
    for item in items:
        merged = _merge(defaults, item)
        alias = str(merged.get("alias") or "").strip()
        if not _ALIAS_RE.match(alias):
            raise InventoryError(f"invalid alias {alias!r}")
        address = str(merged.get("address") or "").strip()
        if not address:
            raise InventoryError(f"{alias}: missing address")
        h = Host(
            alias=alias,
            address=address,
            user=str(merged.get("user") or "root"),
            port=int(merged.get("port") or 22),
            key_file=merged.get("key_file"),
            host_key=merged.get("host_key"),
            tags=tuple(str(t) for t in (merged.get("tags") or ())),
            scopes=tuple(str(s) for s in (merged.get("scopes")
                                          or ("fleet.read", "fleet.exec", "fleet.write"))),
            workdir=merged.get("workdir"),
            env={str(k): str(v) for k, v in (merged.get("env") or {}).items()},
            sudo=bool(merged.get("sudo", False)),
            jump=merged.get("jump"),
            notes=str(merged.get("notes") or ""),
        )
        hosts[h.node_id] = h          # re-registering the same machine overwrites

    for h in hosts.values():
        if h.jump and h.jump not in hosts and not any(
                x.alias == h.jump for x in hosts.values()):
            raise InventoryError(f"{h.alias}: jump target {h.jump} not found")
    return Inventory(hosts=hosts, path=path, mtime=_mtime(path))


# <type> <base64-blob> [comment]. No embedded newline or extra whitespace: a
# host_key is templated into an SSH known_hosts document, and a value with a
# newline would inject additional entries (e.g. a wildcard trusting an attacker
# key). Enrollment supplies this field, so it is untrusted input.
_KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ssh-dss",
              "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
              "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")


def valid_host_key(value: str) -> bool:
    """True if value is exactly one well-formed SSH public host key line."""
    if not value or "\n" in value or "\r" in value:
        return False
    parts = value.split(" ")
    if len(parts) < 2 or parts[0] not in _KEY_TYPES:
        return False
    blob = parts[1]
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception:  # noqa: BLE001
        return False
    # The blob is an SSH string: 4-byte length prefix + the key type repeated.
    if len(raw) < 4:
        return False
    n = int.from_bytes(raw[:4], "big")
    return 4 + n <= len(raw) and raw[4:4 + n].decode("ascii", "replace") == parts[0]


def node_id_of(address: str, port: int, user: str) -> str:
    return "n_" + hashlib.sha256(f"{address}:{port}:{user}".lower().encode()).hexdigest()[:10]


def write_host(path: Path, host: dict) -> Path:
    """Write hosts.d/<node_id>.yaml atomically."""
    alias = str(host.get("alias") or "")
    if not _ALIAS_RE.match(alias):
        raise InventoryError(f"invalid alias {alias!r}")
    nid = node_id_of(str(host["address"]), int(host.get("port") or 22),
                     str(host.get("user") or "ops"))
    d = hosts_d(path)
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise InventoryError(
            f"cannot write {d}; fix with: "
            f"install -d -o vpsmcp -g vpsmcp -m 750 {d}") from exc
    try:
        d.chmod(0o750)
    except OSError:
        pass
    target = d / f"{nid}.yaml"
    body = {"hosts": [{k: v for k, v in host.items() if v not in (None, "", [], {})}]}
    header = (f"# generated by node enrollment; overwritten on re-enrollment\n"
              f"# node_id {nid}   alias {alias}\n"
              f"# remove with: vpsmcp node remove {nid}\n")
    tmp = target.with_suffix(".yaml.tmp")
    tmp.write_text(header + yaml.safe_dump(body, allow_unicode=True, sort_keys=False),
                   encoding="utf-8")
    tmp.replace(target)
    try:
        target.chmod(0o640)
    except OSError:
        pass
    return target


def remove_host(path: Path, node_id: str) -> bool:
    target = hosts_d(path) / f"{node_id}.yaml"
    if target.exists():
        target.unlink()
        return True
    return False


class InventoryWatcher:
    """Lazy reload on mtime change; editing hosts.yaml needs no restart."""

    def __init__(self, path: Path):
        self._path = path
        self._inv = load_inventory(path)

    def get(self) -> Inventory:
        try:
            mtime = _mtime(self._path)
        except OSError:
            return self._inv
        if mtime != self._inv.mtime:
            self._inv = load_inventory(self._path)
        return self._inv
