"""Regression tests for `filezilla --to-clipboard` (stored login password
copy with a displayed secondary confirmation).

Offline drills only: no vault, no GUI, no real clipboard, no writes to the
live settings / site list. Mocks stand in for the native dialog, the TPM
unwrap, the clipboard backend and the FileZilla spawn.

Covers review items A-H:
  A. missing run dir + non-ASCII degrades to False (never raises).
  B. non-ASCII staging lives under wtssh-run-clip-* and is wiped.
  C. _gui_yesno carries the title (not a hardcoded caption).
  D. any book key binding (wtv: or plaintext) refuses --to-clipboard.
  E. documented order only (PIN after site sync) -- no test needed.
  F. login_pw drop is a plain dereference (code comment; no test).
  G. old test-style namespaces without to_clipboard keep working.
  H. password bytes (unicode / trailing newline) ride faithfully.
Plus the exclusion matrix, the exit-2 decline, and the no-leak contract.

Run:  python tests/test_password_clipboard.py
"""
import base64
import io
import json
import os
import sys
import tempfile
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="wtssh-clip-test-"))
FAILURES: list[str] = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


def setup_env():
    os.environ["WTSSH_RUN_DIR"] = str(TMP / "run")
    os.environ["WTSSH_SHIM_DIR"] = str(TMP / "shim")
    os.environ["WTSSH_AUDIT_DIR"] = str(TMP / "log")
    os.environ["WTSSH_NO_HOSTKEY_PROBE"] = "1"
    os.environ["WTSSH_FZ_SITEMANAGER"] = str(TMP / "sitemanager.xml")
    os.environ.pop("WTSSH_FZ_FILEZILLAXML", None)
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    for d in (wtssh.SECRETS_DIR, wtssh.KEYS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    (TMP / "sitemanager.xml").write_text(
        "<FileZilla3><Servers /></FileZilla3>", encoding="utf-8")


def write_settings(entries):
    (TMP / "settings.json").write_text(
        json.dumps({"profiles": {"list": entries}}), encoding="utf-8")


def pw_entry(name="pw1", line="ssh u1@h1.example"):
    return {"name": f"ssh:{name}",
            "guid": "{11111111-0000-0000-0000-000000000001}",
            "commandline": line}


def mkargs(name, **kw):
    base = dict(name=name, keyfile=None, no_open=False, remove_site=False,
                tunnel=False, filezilla=None, to_clipboard=True)
    base.update(kw)
    return types.SimpleNamespace(**base)


class PopenFake:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        return types.SimpleNamespace(wait=lambda timeout=None: 0,
                                     poll=lambda: 0,
                                     terminate=lambda: None)


def run_fz(args, patches):
    saved_sub, saved_exe = wtssh.subprocess.Popen, wtssh.filezilla_exe
    saved = {k: getattr(wtssh, k) for k in patches}
    try:
        for k, v in patches.items():
            setattr(wtssh, k, v)
        wtssh.subprocess.Popen = PopenFake()
        wtssh.filezilla_exe = lambda a: "C:/fake/filezilla.exe"
        out, err = io.StringIO(), io.StringIO()
        raised = None
        with redirect_stdout(out), redirect_stderr(err):
            try:
                wtssh.action_filezilla(args)
            except BaseException as e:  # noqa: BLE001 -- captured into raised
                raised = e
        return out.getvalue(), err.getvalue(), raised, wtssh.subprocess.Popen
    finally:
        for k, v in saved.items():
            setattr(wtssh, k, v)
        wtssh.subprocess.Popen = saved_sub
        wtssh.filezilla_exe = saved_exe


def secret_blob(name="pw1"):
    (wtssh.SECRETS_DIR / f"{name}.bin").write_bytes(b"x")


def test_exclusion_matrix():
    print("[exclusion matrix refuses loudly]")
    write_settings([pw_entry()])
    # no secret
    _, err, raised, _ = run_fz(
        mkargs("pw1"), {"confirm_password_to_clipboard": lambda n, d: True})
    check("no secret dies",
          isinstance(raised, SystemExit) and "no stored passphrase" in str(err)
          or "no stored passphrase" in err, repr(err)[-160:])
    secret_blob()
    # --no-open / --remove-site / --keyfile
    for kw, needle in ((dict(no_open=True), "--no-open"),
                       (dict(remove_site=True), "--remove-site"),
                       (dict(keyfile="C:/k.ppk"), "--keyfile")):
        _, err, raised, _ = run_fz(
            mkargs("pw1", **kw),
            {"confirm_password_to_clipboard": lambda n, d: True})
        check(f"{needle} refused",
              isinstance(raised, SystemExit), repr(raised))
    # vault-key entry
    write_settings([pw_entry("k1", "ssh -i wtv:key1 u@h.example")])
    (wtssh.KEYS_DIR / "key1.wtv").write_bytes(b"x")
    _, err, raised, _ = run_fz(
        mkargs("k1"), {"confirm_password_to_clipboard": lambda n, d: True})
    check("wtv entry refused", isinstance(raised, SystemExit), repr(raised))
    # plaintext-key entry (D)
    write_settings([pw_entry("k2", "ssh -i C:/keys/plain.pem u@h.example")])
    secret_blob("k2")
    _, err, raised, _ = run_fz(
        mkargs("k2"), {"confirm_password_to_clipboard": lambda n, d: True})
    check("plaintext-key entry refused",
          isinstance(raised, SystemExit) and "key-type" in err, repr(err)[-200:])
    # tunnel resolving entries
    write_settings([
        {"name": "ssh:j", "guid": "{22222222-0000-0000-0000-000000000001}",
         "commandline": "ssh u@j.example", "hidden": True},
        {"name": "ssh:t", "guid": "{22222222-0000-0000-0000-000000000002}",
         "commandline": "ssh -J j u@t.example"},
    ])
    secret_blob("t")
    _, _, raised, _ = run_fz(
        mkargs("t", tunnel="yes"),
        {"confirm_password_to_clipboard": lambda n, d: True})
    check("tunnel-yes refused", isinstance(raised, SystemExit), repr(raised))
    _, _, raised, _ = run_fz(
        mkargs("t", tunnel="auto"),
        {"confirm_password_to_clipboard": lambda n, d: True})
    check("tunnel-auto+jump refused",
          isinstance(raised, SystemExit), repr(raised))


def test_decline_exit2_no_launch():
    print("[decline: exit 2, FileZilla never spawned]")
    write_settings([pw_entry()])
    secret_blob()
    popen_holder = {}
    saved_popen = wtssh.subprocess.Popen
    saved_exe = wtssh.filezilla_exe
    saved_confirm = wtssh.confirm_password_to_clipboard
    try:
        fake = PopenFake()
        wtssh.subprocess.Popen = fake
        wtssh.filezilla_exe = lambda a: "C:/fake/filezilla.exe"
        wtssh.confirm_password_to_clipboard = lambda n, d: False
        out, err = io.StringIO(), io.StringIO()
        raised = None
        with redirect_stdout(out), redirect_stderr(err):
            try:
                wtssh.action_filezilla(mkargs("pw1"))
            except BaseException as e:  # noqa: BLE001
                raised = e
        popen_holder["calls"] = fake.calls
    finally:
        wtssh.subprocess.Popen = saved_popen
        wtssh.filezilla_exe = saved_exe
        wtssh.confirm_password_to_clipboard = saved_confirm
    check("decline exits 2",
          isinstance(raised, SystemExit) and raised.code == 2, repr(raised))
    check("decline spawns nothing", popen_holder["calls"] == [],
          repr(popen_holder["calls"]))


def test_happy_path_no_leak():
    print("[happy path: clipboard only, never printed]")
    write_settings([pw_entry()])
    secret_blob()
    secret = "p@ss-秘密123\n"
    copied = []

    def fake_copy(t):
        copied.append(t)
        return True

    out, err, raised, popen = run_fz(
        mkargs("pw1"),
        {"confirm_password_to_clipboard": lambda n, d: True,
         "secret_load": lambda n, ctx: secret,
         "copy_text_to_clipboard": fake_copy})
    check("happy raises nothing", raised is None, repr(raised))
    doc = json.loads(out)
    check("launched", doc.get("launched") is True, out[:200])
    check("passwordClipboard true",
          doc.get("passwordClipboard") is True, out[:300])
    check("auth stays ask", doc.get("auth", {}).get("logontype") == "ask",
          repr(doc.get("auth")))
    check("password not in stdout", secret.strip() not in out, out[:200])
    check("password not in stderr", secret.strip() not in err, err[-200:])
    check("password not in JSON values",
          secret.strip() not in json.dumps(doc), "")
    check("exact bytes incl newline", copied == [secret], repr(copied))
    check("FileZilla spawned once",
          len([c for c in popen.calls if c[0].endswith("filezilla.exe")]) == 1,
          repr(popen.calls))


def test_copy_failure_still_launches():
    print("[copy failure: still launches, never prints]")
    write_settings([pw_entry()])
    secret_blob()
    out, err, raised, popen = run_fz(
        mkargs("pw1"),
        {"confirm_password_to_clipboard": lambda n, d: True,
         "secret_load": lambda n, ctx: "pw-fail-case",
         "copy_text_to_clipboard": lambda t: False})
    check("copy-fail raises nothing", raised is None, repr(raised))
    doc = json.loads(out)
    check("copy-fail still launched", doc.get("launched") is True, out[:200])
    check("passwordClipboard false",
          doc.get("passwordClipboard") is False, out[:300])
    check("copy-fail never prints", "pw-fail-case" not in out + err, err[-200:])


def test_missing_rundir_fail_closed():
    print("[A: missing run root degrades to False]")
    saved = wtssh.make_run_dir
    try:
        def boom(**kw):
            raise OSError("no run dir")
        wtssh.make_run_dir = boom
        check("non-ASCII without run dir returns False",
              wtssh.copy_text_to_clipboard("口令ß") is False, "")
    finally:
        wtssh.make_run_dir = saved


def test_staging_wiped_and_prefixed():
    print("[B/H: staging under wtssh-run-clip-* is wiped, bytes faithful]")
    seen = {}

    def fake_ps(argv, **kw):
        # argv: [powershell, -NoProfile, -Command, ps, path]
        path = Path(argv[-1])
        seen["prefix_ok"] = path.parent.name.startswith("wtssh-run-clip-")
        seen["bytes"] = path.read_bytes()
        return types.SimpleNamespace(returncode=0)

    saved_run = wtssh.subprocess.run
    saved_bin = wtssh.find_bin
    try:
        wtssh.find_bin = lambda n: "C:/fake/powershell.exe" if n == "powershell" else saved_bin(n)
        wtssh.subprocess.run = fake_ps
        secret = "p@ss-秘密123\n"
        check("non-ASCII copy ok",
              wtssh.copy_text_to_clipboard(secret) is True, repr(seen))
    finally:
        wtssh.subprocess.run = saved_run
        wtssh.find_bin = saved_bin
    check("staged under clip run dir", seen.get("prefix_ok") is True,
          repr(seen))
    check("UTF-8 bytes faithful",
          seen.get("bytes") == "p@ss-秘密123\n".encode("utf-8"), repr(seen))
    leftovers = [p for p in (TMP / "run").glob("wtssh-run-clip-*")] \
        if (TMP / "run").exists() else []
    check("staging dir wiped", leftovers == [], repr(leftovers))


def test_gui_yesno_title():
    print("[C: dialog carries the title]")
    captured = {}

    def fake_run(argv, **kw):
        captured["cmd"] = " ".join(argv)
        return types.SimpleNamespace(returncode=0)

    saved_run = wtssh.subprocess.run
    saved_bin = wtssh.find_bin
    try:
        wtssh.find_bin = lambda n: "C:/fake/powershell.exe"
        wtssh.subprocess.run = fake_run
        check("yes returns True",
              wtssh._gui_yesno("body-text", "my-title") is True, "")
    finally:
        wtssh.subprocess.run = saved_run
        wtssh.find_bin = saved_bin
    cmd = captured.get("cmd", "")
    check("title rides base64",
          base64.b64encode("my-title".encode()).decode() in cmd, cmd[-160:])
    check("body rides base64",
          base64.b64encode("body-text".encode()).decode() in cmd, cmd[-160:])


def test_old_namespace_compat():
    print("[G: namespaces without to_clipboard keep working]")
    write_settings([pw_entry()])
    args = types.SimpleNamespace(name="pw1", keyfile=None, no_open=True,
                                 remove_site=False, tunnel="auto",
                                 filezilla=None)  # no to_clipboard field
    out, err = io.StringIO(), io.StringIO()
    raised = None
    with redirect_stdout(out), redirect_stderr(err):
        try:
            wtssh.action_filezilla(args)
        except BaseException as e:  # noqa: BLE001
            raised = e
    check("legacy ns syncs without AttributeError", raised is None,
          repr(raised))
    # companion lines never carry --to-clipboard
    check("companion stays --tunnel auto",
          wtssh.sftp_line("pw1").endswith(" filezilla pw1 --tunnel auto"),
          wtssh.sftp_line("pw1"))


def main():
    setup_env()
    test_exclusion_matrix()
    test_decline_exit2_no_launch()
    test_happy_path_no_leak()
    test_copy_failure_still_launches()
    test_missing_rundir_fail_closed()
    test_staging_wiped_and_prefixed()
    test_gui_yesno_title()
    test_old_namespace_compat()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} -> {FAILURES}")
        return 1
    print("all password-clipboard tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
