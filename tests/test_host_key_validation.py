"""host_key from enrollment is templated into an SSH known_hosts document, so it
must be a single well-formed key line. A value with an embedded newline could add
extra known_hosts entries (e.g. a wildcard). This is defence in depth - the
known_hosts object is built per connection and used only for that node today - but
untrusted key material should never reach a structured format unvalidated.

Pure unit test. Generates a real ed25519 key so the base64 blob is genuine.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import asyncssh  # noqa: E402
from vpsmcp.inventory import valid_host_key  # noqa: E402

pub = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()
kind, blob = pub.split()[0], pub.split()[1]

# accepted
assert valid_host_key(pub), "real key with comment rejected"
assert valid_host_key(f"{kind} {blob}"), "real key without comment rejected"
print("1. a genuine ed25519 host key is accepted (with and without a comment)")

# rejected: injection and malformed
bad = {
    "empty": "",
    "newline injection": f"{kind} {blob}\n*  {kind} {blob}",
    "crlf injection": f"{kind} {blob}\r\n1.2.3.4 {kind} {blob}",
    "leading newline": f"\n{kind} {blob}",
    "not base64": f"{kind} not+valid+base64!!",
    "type/blob mismatch": f"ssh-rsa {blob}",   # blob encodes ssh-ed25519
    "unknown type": f"ssh-ed99999 {blob}",
    "no blob": kind,
    "command-like": "rm -rf /",
}
for name, value in bad.items():
    assert not valid_host_key(value), f"should reject: {name}: {value!r}"
print(f"2. rejects {len(bad)} malformed / injection variants (newline, CRLF, "
      f"bad type, bad base64, type-blob mismatch)")

print("\nall host-key validation checks passed")
