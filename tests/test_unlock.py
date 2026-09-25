"""`vpsmcp unlock` clears the admin-login lockout (login_attempts).

After 5 failed logins from an IP the consent-page login is locked with an
exponential backoff; unlock removes those rows so login works again immediately.
"""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.auth.store import Store  # noqa: E402

db = Path(tempfile.mkdtemp()) / "oauth.db"
s = Store(db)

# no locks yet
assert s.login_locks() == []
assert s.clear_login_locks() == 0
print("1. nothing to clear on a fresh store")

# trip the lockout for two IPs
for _ in range(6):
    s.login_failed("203.0.113.7")
for _ in range(6):
    s.login_failed("198.51.100.9")
assert s.login_locked("203.0.113.7") > 0, "IP should be locked after 6 fails"
locks = {l["ip"] for l in s.login_locks()}
assert locks == {"203.0.113.7", "198.51.100.9"}, locks
print("2. two IPs locked out after repeated failures")

# clear one
assert s.clear_login_locks("203.0.113.7") == 1
assert s.login_locked("203.0.113.7") == 0
assert s.login_locked("198.51.100.9") > 0
print("3. unlock <ip> clears just that IP")

# clear the rest
assert s.clear_login_locks() == 1
assert s.login_locks() == []
assert s.login_locked("198.51.100.9") == 0
print("4. unlock (no arg) clears all remaining lockouts")

print("\nall unlock checks passed")
