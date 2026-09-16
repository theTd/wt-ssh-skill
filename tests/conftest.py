"""pytest guard: never let the suite touch the live config.

Incident: every test module keeps its sandbox in `setup_env()`, which only
runs via `main()` (i.e. `python tests/test_x.py`). Under bare `pytest`,
`test_*` functions execute WITHOUT any setup, so `wtssh.SETTINGS` /
vault dirs / FileZilla hooks resolve to the LIVE user config -- one run
overwrote the real `settings.json` (and its `.wtssh.bak`) with fixtures.
Per SKILL.md section 8, drills must never write the live config.

Two layers, both fail-closed toward temp dirs:

1. Import time (this file loads before any test module): pin every live
   path -- `wtssh.SETTINGS` / `SECRETS_DIR` / `KEYS_DIR` and the
   `WTSSH_*` env hooks -- at a session-scoped temp dir, so even
   collection-time code cannot reach the user config.
2. Per-test autouse fixture: snapshot the full environment plus the three
   `wtssh` path attrs, run the test module's own `setup_env()` when it
   has one (each module's exact fixture contract wins), then restore.
   `PYTEST_*` vars are left alone so pytest's own bookkeeping survives.

Script runs (`python tests/test_x.py`) are unaffected: `main()` still
calls `setup_env()` into the module's own TMP dir as before.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

GUARD = Path(tempfile.mkdtemp(prefix="wtssh-pytest-guard-"))
(GUARD / "secrets").mkdir(parents=True, exist_ok=True)
(GUARD / "keys").mkdir(parents=True, exist_ok=True)
(GUARD / "run").mkdir(parents=True, exist_ok=True)
(GUARD / "shim").mkdir(parents=True, exist_ok=True)
(GUARD / "log").mkdir(parents=True, exist_ok=True)
(GUARD / "settings.json").write_text(
    json.dumps({"profiles": {"list": []}}), encoding="utf-8")

os.environ["WTSSH_RUN_DIR"] = str(GUARD / "run")
os.environ["WTSSH_SHIM_DIR"] = str(GUARD / "shim")
os.environ["WTSSH_AUDIT_DIR"] = str(GUARD / "log")
os.environ["WTSSH_AGENT_DIR"] = str(GUARD / "agent")
(GUARD / "agent").mkdir(parents=True, exist_ok=True)
os.environ["WTSSH_FZ_SITEMANAGER"] = str(GUARD / "sitemanager.xml")
os.environ["WTSSH_FZ_FILEZILLAXML"] = str(GUARD / "filezilla.xml")
(GUARD / "sitemanager.xml").write_text(
    '<?xml version="1.0"?><FileZilla3><Servers /></FileZilla3>',
    encoding="utf-8")

wtssh.SETTINGS = GUARD / "settings.json"
wtssh.SECRETS_DIR = GUARD / "secrets"
wtssh.KEYS_DIR = GUARD / "keys"
wtssh.AGENT_DIR = GUARD / "agent"

_PATH_ATTRS = ("SETTINGS", "SECRETS_DIR", "KEYS_DIR", "AGENT_DIR")


@pytest.fixture(autouse=True)
def _wtssh_isolation(request):
    """Redirect each test at its own module sandbox, restore afterwards."""
    saved_env = dict(os.environ)
    saved_attrs = {k: getattr(wtssh, k, None) for k in _PATH_ATTRS}
    setup = getattr(request.module, "setup_env", None)
    if callable(setup):
        setup()
    try:
        yield
    finally:
        keep = {k: v for k, v in os.environ.items()
                if k.startswith("PYTEST_")}
        os.environ.clear()
        os.environ.update(saved_env)
        os.environ.update(keep)
        for k, v in saved_attrs.items():
            setattr(wtssh, k, v)
