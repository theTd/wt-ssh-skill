"""Offline drill tests for the askpass dispatcher + connect dispatch (no
vault, no real ssh, no writes to the live settings/vault):

  1. dispatcher schema v2: key slot (full / truncated / casefold / tombstone /
     unregistered), login slot (identity gate, uses countdown, shape gate,
     host-key + kbdint prompts refused), strict v2 parsing (flat legacy map
     refused).
  2. legacy connect path wiring (monkeypatched vault/ssh): map written in
     v2, env carries WTSSH_ASKPASS_MAP and NEVER WTSSH_PASSPHRASE,
     -o hardening per credential type, --no-askpass honored (B0), session
     dirs wiped afterwards.
  3. write->read round trip: the exact map file connect wrote is served by
     the dispatcher.

Run:  python tests/test_dispatcher.py
"""
import io
import json
import os
import sys
import tempfile
import types
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-"))
FAILURES: list[str] = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


# ----------------------------------------------------------- dispatcher unit

def run_askpass(prompt: str, *, map_obj=None, raw=None, with_env=True,
                gui=False):
    map_path = TMP / "unit-map.json"
    if raw is not None:
        map_path.write_text(raw, encoding="utf-8")
    else:
        map_path.write_text(json.dumps(map_obj), encoding="utf-8")
    old_map = os.environ.get("WTSSH_ASKPASS_MAP")
    old_gui = os.environ.get("WTSSH_ASKPASS_GUI")
    if with_env:
        os.environ["WTSSH_ASKPASS_MAP"] = str(map_path)
    else:
        os.environ.pop("WTSSH_ASKPASS_MAP", None)
    if gui:
        os.environ["WTSSH_ASKPASS_GUI"] = "1"
    out, err = io.StringIO(), io.StringIO()
    args = types.SimpleNamespace(prompt=prompt.split())
    try:
        with redirect_stdout(out), redirect_stderr(err):
            wtssh.action_askpass(args)
    finally:
        os.environ.pop("WTSSH_ASKPASS_MAP", None)
        if old_map is not None:
            os.environ["WTSSH_ASKPASS_MAP"] = old_map
        os.environ.pop("WTSSH_ASKPASS_GUI", None)
        if old_gui is not None:
            os.environ["WTSSH_ASKPASS_GUI"] = old_gui
    return out.getvalue(), err.getvalue()


LONG_DIR = "d" * 120
KEY_PATH = f"/{LONG_DIR}/key"
KEY_MAP_KEY = KEY_PATH[:wtssh.ASKPASS_PROMPT_MAX]


def v2(keys=None, login=None):
    return {"v": wtssh.MAP_SCHEMA_VERSION, "keys": keys or {},
            "login": login}


def unit_tests():
    print("[dispatcher: keys slot]")
    out, _ = run_askpass(f"Enter passphrase for key '{KEY_PATH}': ",
                         map_obj=v2({KEY_MAP_KEY: {"pw": "K1", "uses": 1}}))
    check("key full/truncated hit", out == "K1\n", repr(out))

    out, err = run_askpass(f"Enter passphrase for key '/other/key': ",
                           map_obj=v2({KEY_MAP_KEY: {"pw": "K1", "uses": 1}}))
    check("key unregistered -> empty + reason",
          out == "\n" and "not registered" in err, repr((out, err)))

    out, err = run_askpass(f"Enter passphrase for key '{KEY_PATH}': ",
                         map_obj=v2({KEY_MAP_KEY: None}))
    out2, err2 = run_askpass(f"Enter passphrase for key '{KEY_PATH}': ",
                             map_obj=v2({KEY_MAP_KEY.lower(): None}))
    check("key tombstone (exact + casefold)",
          out == "\n" and out2 == "\n"
          and "already handed out" in err and "already handed out" in err2,
          repr((out, err, out2, err2)))

    out, _ = run_askpass("some server banner text",
                         map_obj=v2({KEY_MAP_KEY: {"pw": "K1", "uses": 1}}))
    check("non-key prompt never served from keys slot", out == "\n")

    # one-shot consumed: after a serve the on-disk map holds a tombstone
    mp = TMP / "consume.json"
    mp.write_text(json.dumps(v2({KEY_MAP_KEY: {"pw": "K1", "uses": 1}})))
    old = os.environ.get("WTSSH_ASKPASS_MAP")
    os.environ["WTSSH_ASKPASS_MAP"] = str(mp)
    try:
        args = types.SimpleNamespace(
            prompt=f"Enter passphrase for key '{KEY_PATH}': ".split())
        buf = io.StringIO()
        with redirect_stdout(buf):
            wtssh.action_askpass(args)
        on_disk = json.loads(mp.read_text(encoding="utf-8"))
    finally:
        os.environ.pop("WTSSH_ASKPASS_MAP", None)
        if old is not None:
            os.environ["WTSSH_ASKPASS_MAP"] = old
    check("key one-shot: served + tombstone persisted",
          buf.getvalue() == "K1\n" and on_disk["keys"][KEY_MAP_KEY] is None,
          repr(on_disk))

    print("[dispatcher: login slot]")
    login = {"pw": "P1", "uses": 3,
             "identities": ["alice@h4.example"]}
    # persistent map file written ONCE: the countdown must survive across
    # dispatches (3 serves, then exhausted)
    mp = TMP / "login-count.json"
    mp.write_text(json.dumps(v2(login=dict(login))))
    old = os.environ.get("WTSSH_ASKPASS_MAP")
    os.environ["WTSSH_ASKPASS_MAP"] = str(mp)
    try:
        for i in range(3):
            buf, ebuf = io.StringIO(), io.StringIO()
            with redirect_stdout(buf), redirect_stderr(ebuf):
                wtssh.action_askpass(types.SimpleNamespace(
                    prompt="alice@h4.example's password: ".split()))
            on_disk = json.loads(mp.read_text(encoding="utf-8"))
            check(f"login hit #{i + 1} (uses {3 - i} -> {2 - i})",
                  buf.getvalue() == "P1\n"
                  and on_disk["login"]["uses"] == 2 - i,
                  repr((buf.getvalue(), on_disk["login"])))
    finally:
        os.environ.pop("WTSSH_ASKPASS_MAP", None)
        if old is not None:
            os.environ["WTSSH_ASKPASS_MAP"] = old
    out, err = run_askpass("alice@h4.example's password: ", raw=mp.read_text(
        encoding="utf-8"))
    check("login uses exhausted -> miss",
          out == "\n" and "exhausted" in err, repr((out, err)))

    out, err = run_askpass("mallory@h4.example's password: ",
                           map_obj=v2(login=dict(login)))
    check("login wrong identity -> miss",
          out == "\n" and "not registered for login dispatch" in err,
          repr(err))

    out, err = run_askpass("alice@h4.example's password: ",
                           map_obj=v2(login=None))
    check("no login slot -> miss", out == "\n" and "no login credential" in err)

    for prompt in ("Password: ", "Verification code: ",
                   "The authenticity of host 'h' can't be established.",
                   "Enter passphrase for key '/x': "):
        out, _ = run_askpass(prompt, map_obj=v2(login=dict(login)))
        check(f"login never serves non-registered shape: {prompt[:28]!r}",
              out == "\n")

    print("[dispatcher: strict schema]")
    for name, payload in (
            ("flat legacy map refused", {KEY_MAP_KEY: {"pw": "K"}}),
            ("missing v refused", {"keys": {}, "login": None}),
            ("wrong v refused", {"v": 1, "keys": {}, "login": None}),
            ("garbage refused", "not json at all")):
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        out, err = run_askpass("alice@h4.example's password: ", raw=raw)
        check(name, out == "\n" and ("schema 2" in err or "unreadable" in err),
              repr((out, err)))

    out, _ = run_askpass("x", with_env=False)
    check("no map registered -> miss", out == "\n")

    print("[dispatcher: probe GUI carve-out]")
    dialogs: list[str] = []
    saved_gui = wtssh._gui_yesno
    wtssh._gui_yesno = (lambda text, title:
                        dialogs.append(text) or False)
    try:
        out, _ = run_askpass(f"Enter passphrase for key '{KEY_PATH}': ",
                             map_obj=v2({KEY_MAP_KEY: None}), gui=True)
        check("gui carve-out: key-shaped miss must NOT dialog",
              out == "\n" and dialogs == [], repr((out, dialogs)))
        out, _ = run_askpass(
            "The authenticity of host 'h' can't be established.",
            map_obj=v2(), gui=True)
        check("gui: non-key miss dialogs once, decline answers 'no'",
              out == "no\n" and len(dialogs) == 1, repr((out, dialogs)))
    finally:
        wtssh._gui_yesno = saved_gui


# ------------------------------------------------------- connect integration

class FakeRun:
    """subprocess.run stand-in: stashes argv/env and the mid-flight map file
    (the real wipe happens only after this returns)."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, env=None, **kw):
        entry = {"argv": list(argv), "env": dict(env or {}), "map": None}
        mp = (env or {}).get("WTSSH_ASKPASS_MAP")
        if mp and Path(mp).exists():
            entry["map"] = json.loads(Path(mp).read_text(encoding="utf-8"))
        self.calls.append(entry)
        return types.SimpleNamespace(returncode=0)


def setup_env():
    os.environ["WTSSH_RUN_DIR"] = str(TMP / "run")
    os.environ["WTSSH_SHIM_DIR"] = str(TMP / "shim")
    os.environ["WTSSH_AUDIT_DIR"] = str(TMP / "log")
    os.environ["WTSSH_NO_HOSTKEY_PROBE"] = "1"
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    wtssh.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    wtssh.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    (wtssh.KEYS_DIR / "key1.wtv").write_bytes(b"x")
    (wtssh.SECRETS_DIR / "stored.bin").write_bytes(b"x")
    (TMP / "settings.json").write_text(json.dumps({
        "profiles": {"list": [
            {"name": "ssh:single",
             "guid": "{aaaaaaaa-0000-0000-0000-000000000001}",
             "commandline": "ssh -i wtv:key1 u@h9.example",
             "hidden": False},
            {"name": "ssh:stored",
             "guid": "{aaaaaaaa-0000-0000-0000-000000000002}",
             "commandline": "ssh alice@h4.example",
             "hidden": False},
        ]}}), encoding="utf-8")


def connect(name, *, no_askpass=False, fake):
    saved = {}
    saved["payload"] = wtssh.vault_open_payload
    saved["secret"] = wtssh.secret_load
    saved["mkkey"] = wtssh.secure_mkkey
    saved["run"] = wtssh.subprocess.run
    saved["probe"] = wtssh.probe_host_keys
    saved["support"] = wtssh.ssh_askpass_support
    saved["sweeprun"] = wtssh.sweep_orphan_rundirs
    sweeps: list[int] = []
    wtssh.vault_open_payload = lambda kind, name, raw, what, ctx, dek=None: {
        "fmt": 4, "name": name, "key": "QUFB", "passphrase": "KEYPW"}
    wtssh.secret_load = (lambda name, ctx: (_ for _ in ()).throw(
        AssertionError("secret_load must not run"))) \
        if no_askpass else (lambda name, ctx: "LOGINPW")
    keydir = TMP / "fakekey"
    keydir.mkdir(parents=True, exist_ok=True)
    (keydir / "key").write_bytes(b"container")
    wtssh.secure_mkkey = lambda data: (keydir, keydir / "key")
    wtssh.subprocess.run = fake
    wtssh.probe_host_keys = lambda dests, strict=True: None
    wtssh.ssh_askpass_support = lambda: (True, "OpenSSH 9.9")
    wtssh.sweep_orphan_rundirs = lambda *a, **k: sweeps.append(1)
    args = types.SimpleNamespace(name=name, extra=[], tunnel_forward=None,
                                 no_askpass=no_askpass)
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            wtssh.action_connect(args)
    except SystemExit:
        pass  # action_connect ends with sys.exit(rc) on the happy path
    finally:
        wtssh.vault_open_payload = saved["payload"]
        wtssh.secret_load = saved["secret"]
        wtssh.secure_mkkey = saved["mkkey"]
        wtssh.subprocess.run = saved["run"]
        wtssh.probe_host_keys = saved["probe"]
        wtssh.ssh_askpass_support = saved["support"]
        wtssh.sweep_orphan_rundirs = saved["sweeprun"]
    return sweeps


def integration_tests():
    print("[connect: single vault key]")
    fake = FakeRun()
    sweeps = connect("single", fake=fake)
    call = fake.calls[0]
    env = call["env"]
    check("orphan run-dir sweeper runs on legacy connect (R7)",
          sweeps == [1], repr(sweeps))
    check("env carries dispatcher + map",
          env.get("SSH_ASKPASS_REQUIRE") == "force"
          and bool(env.get("SSH_ASKPASS"))
          and bool(env.get("WTSSH_ASKPASS_MAP")))
    check("env NEVER carries WTSSH_PASSPHRASE",
          "WTSSH_PASSPHRASE" not in env and "WTSSH_PASSPHRASE" not in " ".join(call["argv"]))
    check("password channels shut off for key entries",
          "PasswordAuthentication=no" in call["argv"])
    m = call["map"]
    check("map is schema v2, keys slot served once, login empty",
          m["v"] == wtssh.MAP_SCHEMA_VERSION
          and list(m["keys"].values()) == [{"pw": "KEYPW", "uses": 1}]
          and m["login"] is None, repr(m))
    # the exact map file connect wrote must be served by the dispatcher
    out, err = run_askpass(
        f"Enter passphrase for key '{TMP / 'fakekey' / 'key'}': ",
        raw=json.dumps(m))
    check("write->read round trip serves KEYPW", out == "KEYPW\n",
          repr((out, err)))
    check("session dirs wiped after connect",
          not (TMP / "fakekey").exists()
          and not any((TMP / "run").glob("wtssh-run-*") if (TMP / "run").exists() else []))

    print("[connect: stored secret (Option A)]")
    fake = FakeRun()
    connect("stored", fake=fake)
    call = fake.calls[0]
    env, argv, m = call["env"], call["argv"], call["map"]
    check("stored: no WTSSH_PASSPHRASE, map registered",
          "WTSSH_PASSPHRASE" not in env
          and bool(env.get("WTSSH_ASKPASS_MAP")))
    check("stored: kbdint shut off + prompts pinned to uses=3",
          "ChallengeResponseAuthentication=no" in argv
          and "NumberOfPasswordPrompts=3" in argv
          and "PasswordAuthentication=no" not in argv, repr(argv))
    check("stored: login slot with registered identity, uses=3",
          m["login"] == {"pw": "LOGINPW", "uses": 3,
                         "identities": ["alice@h4.example"]}
          and m["keys"] == {}, repr(m))
    check("stored: no leftover run dirs",
          not any((TMP / "run").glob("wtssh-run-*") if (TMP / "run").exists() else []))

    print("[connect: --no-askpass (B0)]")
    fake = FakeRun()
    connect("stored", no_askpass=True, fake=fake)
    call = fake.calls[0]
    check("B0 stored: no askpass env at all",
          not any(k.startswith(("SSH_ASKPASS", "WTSSH_ASKPASS")) or
                  k == "WTSSH_PASSPHRASE" for k in call["env"]),
          repr([k for k in call["env"] if "ASKPASS" in k or "PASSPHRASE" in k]))
    check("B0 stored: no -o insertion, no map file",
          "ChallengeResponseAuthentication=no" not in call["argv"]
          and "NumberOfPasswordPrompts=3" not in call["argv"]
          and call["map"] is None)

    fake = FakeRun()
    connect("single", no_askpass=True, fake=fake)
    call = fake.calls[0]
    check("B0 key: unwrapped container but dispatch OFF",
          not any(k.startswith(("SSH_ASKPASS", "WTSSH_ASKPASS")) or
                  k == "WTSSH_PASSPHRASE" for k in call["env"])
          and call["map"] is None
          and "PasswordAuthentication=no" in call["argv"])


def main():
    setup_env()
    unit_tests()
    integration_tests()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} -> {FAILURES}")
        return 1
    print("all dispatcher/connect tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
