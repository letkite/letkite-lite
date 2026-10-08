"""An explicit node_id in the inventory keeps a host's id across an address change.

node_id is computed from address:port:user, so moving a host to another address
(say from its public IP to a VPN address) gives it a new id and orphans anything
keyed by the old one. A hand-written entry may set node_id itself; it is used
as-is when it matches the n_<hex> format, and the computed id stays the fallback.

Pure unit test, no server needed.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.inventory import (InventoryError, load_inventory, node_id_of,  # noqa: E402
                              remove_host, write_host)

d = Path(tempfile.mkdtemp())
inv_path = d / "hosts.yaml"


def load(yaml_text):
    inv_path.write_text(yaml_text, encoding="utf-8")
    return load_inventory(inv_path)


# 1. no node_id: the computed id, unchanged from before
inv = load("defaults: {user: ops}\nhosts:\n  - {alias: web-1, address: 203.0.113.10}\n")
old = node_id_of("203.0.113.10", 22, "ops")
assert list(inv.hosts) == [old], inv.hosts
print("1. without node_id the id is computed from address:port:user")

# 2. pinned to the old id, the host keeps it after moving to its VPN address
inv = load(f"defaults: {{user: ops}}\nhosts:\n"
           f"  - {{alias: web-1, address: 10.8.0.2, node_id: {old}}}\n")
h = inv.get(old)
assert h.address == "10.8.0.2" and h.node_id == old, h
assert inv.get("web-1").node_id == old
print("2. an explicit node_id is used as-is and survives the address change")

# 3. invalid ids are refused; node_id in defaults is ignored (it would merge hosts)
for bad in ("web-1", "n_XYZ", "n_123", "../../etc/x", "n_" + "a" * 33, "N_0123456789"):
    try:
        load(f"hosts:\n  - {{alias: web-1, address: 10.8.0.2, node_id: '{bad}'}}\n")
    except InventoryError as exc:
        assert "node_id" in str(exc), exc
    else:
        raise AssertionError(f"accepted invalid node_id {bad!r}")
inv = load(f"defaults: {{user: ops, node_id: {old}}}\nhosts:\n"
           f"  - {{alias: a, address: 10.8.0.2}}\n  - {{alias: b, address: 10.8.0.3}}\n")
assert len(inv.hosts) == 2 and old not in inv.hosts, inv.hosts
print("3. malformed node_ids are refused; a node_id under defaults does not apply")

# 4. hosts.d keeps the explicit id when a node is rewritten (node scopes/rename/tags)
target = write_host(inv_path, {"alias": "web-1", "address": "10.8.0.2", "user": "ops",
                               "scopes": ["fleet.read"], "node_id": old})
assert target.name == f"{old}.yaml", target
inv = load_inventory(inv_path)
assert inv.get(old).scopes == ("fleet.read",) and inv.get(old).address == "10.8.0.2"
assert remove_host(inv_path, old)
target = write_host(inv_path, {"alias": "web-2", "address": "10.8.0.9", "user": "ops"})
assert target.name == f"{node_id_of('10.8.0.9', 22, 'ops')}.yaml", target
print("4. write_host names the file after the explicit id, computed id otherwise")

# 5. the same explicit id on two different machines is refused, naming both; the
#    same machine listed twice still overwrites
try:
    load(f"defaults: {{user: ops}}\nhosts:\n"
         f"  - {{alias: web-1, address: 10.8.0.2, node_id: {old}}}\n"
         f"  - {{alias: db-1, address: 10.8.0.3, node_id: {old}}}\n")
except InventoryError as exc:
    assert "db-1" in str(exc) and "web-1" in str(exc) and old in str(exc), exc
else:
    raise AssertionError("accepted one node_id for two machines")
inv = load(f"defaults: {{user: ops}}\nhosts:\n"
           f"  - {{alias: web-1, address: 10.8.0.2, node_id: {old}}}\n"
           f"  - {{alias: web-1b, address: 10.8.0.2, node_id: {old}}}\n")
assert inv.hosts[old].alias == "web-1b" and \
    all(h.alias != "web-1" for h in inv.hosts.values()), inv.hosts
print("5. one explicit node_id on two machines is refused; the same machine twice overwrites")

print("\nall node-id checks passed")
