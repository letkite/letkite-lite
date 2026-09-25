"""`vpsmcp setup` re-prompts for the admin password instead of aborting.

A too-short password or a mismatched repeat used to `return 2` and end the whole
setup run; now prompt_admin_password loops until it gets a good password or an
empty entry (which means "generate one").

Pure unit test.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.setup import prompt_admin_password, MIN_PASSWORD_LEN  # noqa: E402


def scripted(inputs):
    """Return an ask() that yields the given answers in order (like getpass)."""
    it = iter(inputs)

    def ask(_prompt):
        return next(it)
    return ask


def run(inputs):
    msgs = []
    pw = prompt_admin_password(ask=scripted(inputs), notify=msgs.append)
    return pw, msgs


good = "correct-horse-battery"        # >= 12 chars
assert len(good) >= MIN_PASSWORD_LEN

# 1. empty -> generate (None), no error
pw, msgs = run([""])
assert pw is None and msgs == [], (pw, msgs)
print("1. empty entry returns None (generate) with no error")

# 2. valid on the first try
pw, msgs = run([good, good])
assert pw == good and msgs == [], (pw, msgs)
print("2. a valid, matching password is accepted")

# 3. too short, then valid: retried, not aborted
pw, msgs = run(["short", good, good])
assert pw == good, pw
assert len(msgs) == 1 and "at least" in msgs[0], msgs
print("3. too-short password re-prompts, then succeeds")

# 4. mismatch, then valid: retried, not aborted
pw, msgs = run([good, "different-but-long", good, good])
assert pw == good, pw
assert len(msgs) == 1 and "match" in msgs[0], msgs
print("4. mismatched repeat re-prompts, then succeeds")

# 5. several failures in a row (two too-short, then a mismatch), then give up and
#    generate by entering empty
pw, msgs = run(["x", "alsoshort", good, "nope-long-enough", ""])
assert pw is None, pw
assert len(msgs) == 3, msgs  # short, short, mismatch
print("5. repeated failures keep prompting; empty finally falls back to generate")

print("\nall setup password-prompt checks passed")
