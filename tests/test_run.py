"""Offline drill tests for `run` / bare-form native-style execution (no
vault, no real ssh, no writes to the live settings/vault):

  1. bare-form rewrite: `wtssh NAME [cmd...]` gains an implicit `run`;
     subcommands, flags and globals are left alone.
  2. remote command plumbing: appended after the destination on the legacy
     path, `--` stripped, tail conflict dies loudly, --tunnel-forward
     conflict dies loudly, empty command == connect.
  3. stdout purity: the run path writes nothing to stdout (dry-run JSON
     reroutes to stderr); exit code is ssh's.
  4. rendered plumbing: rebuild_target_argv keeps the command after the
     opaque block.

Run:  python tests/test_run.py
"""
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

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-run-"))
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
    os.environ.pop("WTSSH_RENDER_DRY", None)
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    for d in (wtssh.KEYS_DIR, wtssh.SECRETS_DIR,
              TMP / "run", TMP / "shim", TMP / "log"):
        d.mkdir(parents=True, exist_ok=True)
    (wtssh.KEYS_DIR / "key1.wtv").write_bytes(b"x")
    (TMP / "settings.json").write_text(json.dumps({
        "profiles": {"list": [
            {"name": "ssh:plain",
             "guid": "{cccccccc-0000-0000-0000-000000000001}",
             "commandline": "ssh alice@h4.example",
             "hidden": False},
            {"name": "ssh:tail",
             "guid": "{cccccccc-0000-0000-0000-000000000002}",
             "commandline": "ssh alice@h4.example echo hi",
             "hidden": False},
            {"name": "ssh:vaulted",
             "guid": "{cccccccc-0000-0000-0000-000000000003}",
             "commandline": "ssh -i wtv:key1 u@h9.example",
             "hidden": False},
            {"name": "ssh:pwlogin",
             "guid": "{cccccccc-0000-0000-0000-000000000004}",
             "commandline": "ssh bob@h5.example",
             "hidden": False},
        ]}}), encoding="utf-8")
    (wtssh.SECRETS_DIR / "pwlogin.bin").write_bytes(b"x")


class FakeRun:
    """subprocess.run stand-in: records argv/env (+ mid-flight askpass map,
    which the real wipe removes after return), exits with a fixed code."""

    def __init__(self, rc=0):
        self.calls = []
        self.rc = rc

    def __call__(self, argv, env=None, **kw):
        entry = {"argv": list(argv), "env": dict(env or {}), "map": None}
        mp = (env or {}).get("WTSSH_ASKPASS_MAP")
        if mp and Path(mp).exists():
            entry["map"] = json.loads(Path(mp).read_text(encoding="utf-8"))
        self.calls.append(entry)
        return types.SimpleNamespace(returncode=self.rc)


def run_args(name, command, **kw):
    d = {"name": name, "extra": [], "tunnel_forward": None,
         "no_askpass": False, "no_agent": False, "command": command,
         "cmd": "run"}
    d.update(kw)
    return types.SimpleNamespace(**d)


def test_bare_rewrite():
    ap = wtssh.build_parser()
    rw = wtssh._bare_run_rewrite
    check("bare NAME + cmd gains run",
          rw(ap, ["alpha", "uptime"]) == ["run", "alpha", "uptime"])
    check("bare NAME alone gains run",
          rw(ap, ["alpha"]) == ["run", "alpha"])
    check("subcommands untouched",
          rw(ap, ["list"]) == ["list"]
          and rw(ap, ["connect", "x"]) == ["connect", "x"]
          and rw(ap, ["run", "x", "y"]) == ["run", "x", "y"])
    check("flags untouched",
          rw(ap, ["-h"]) == ["-h"] and rw(ap, ["--help"]) == ["--help"]
          and rw(ap, []) == [])
    check("globals skipped",
          rw(ap, ["--settings", "X", "--group", "g", "alpha", "uptime"])
          == ["--settings", "X", "--group", "g", "run", "alpha", "uptime"])
    check("globals =-form skipped",
          rw(ap, ["--settings=X", "alpha"]) == ["--settings=X", "run", "alpha"])
    check("subcommand after globals untouched",
          rw(ap, ["--settings", "X", "list"]) == ["--settings", "X", "list"])
    import argparse
    sub = next(a for a in ap._actions
               if isinstance(a, argparse._SubParsersAction))
    check("SUBCOMMANDS matches the parser (no drift)",
          set(sub.choices) == wtssh.SUBCOMMANDS,
          repr(sorted(set(sub.choices) ^ wtssh.SUBCOMMANDS)))


def test_run_parser():
    ap = wtssh.build_parser()
    a = ap.parse_args(["run", "alpha", "--", "ls", "-l"])
    check("argparse strips the separator itself",
          a.command == ["ls", "-l"], repr(a.command))
    a = ap.parse_args(["run", "alpha", "uptime", "-p"])
    check("flags after NAME are command text",
          a.command == ["uptime", "-p"], repr(a.command))
    a = ap.parse_args(["run", "--no-askpass", "alpha"])
    check("options before NAME parse, empty command",
          a.no_askpass is True and a.name == "alpha" and a.command == [],
          repr(a))
    a = ap.parse_args(["run", "--", "alpha"])
    check("dashdash allows flag-like names",
          a.name == "alpha" and a.command == [], repr(a))


def do_run(args, fake, *, dry=False):
    """Run action_connect with ssh mocked; return (exit_code, stdout, stderr)."""
    saved = (wtssh.subprocess.run, wtssh.probe_host_keys,
             wtssh.sweep_orphan_keydirs, wtssh.sweep_orphan_rundirs)
    wtssh.subprocess.run = fake
    wtssh.probe_host_keys = lambda dests, strict=True: None
    wtssh.sweep_orphan_keydirs = lambda *a, **k: None
    wtssh.sweep_orphan_rundirs = lambda *a, **k: None
    if dry:
        os.environ["WTSSH_RENDER_DRY"] = "1"
    out, err = io.StringIO(), io.StringIO()
    code = None
    try:
        with redirect_stdout(out), redirect_stderr(err):
            wtssh.action_connect(args)
    except SystemExit as e:
        code = e.code
    finally:
        (wtssh.subprocess.run, wtssh.probe_host_keys,
         wtssh.sweep_orphan_keydirs,
         wtssh.sweep_orphan_rundirs) = saved
        os.environ.pop("WTSSH_RENDER_DRY", None)
    return code, out.getvalue(), err.getvalue()


def mock_vault():
    """Mock the vault touchpoints of the legacy single-key path."""
    saved = (wtssh.vault_open_payload, wtssh.secure_mkkey,
             wtssh.ssh_askpass_support)
    wtssh.vault_open_payload = lambda kind, name, raw, what, ctx, dek=None: {
        "fmt": 4, "name": name, "key": "QUFB", "passphrase": "KEYPW"}
    keydir = TMP / "fakekey"
    keydir.mkdir(parents=True, exist_ok=True)
    (keydir / "key").write_bytes(b"container")
    wtssh.secure_mkkey = lambda data, cleartext=False: (keydir, keydir / "key")
    wtssh.ssh_askpass_support = lambda: (True, "OpenSSH 9.9")
    return saved


def unmock_vault(saved):
    (wtssh.vault_open_payload, wtssh.secure_mkkey,
     wtssh.ssh_askpass_support) = saved


def test_run_appends_command():
    fake = FakeRun()
    code, out, _ = do_run(run_args("plain", ["uptime", "-p"]), fake)
    check("plain run exit 0", code == 0, repr(code))
    check("command appended after destination",
          fake.calls and fake.calls[0]["argv"][-3:] == ["alice@h4.example",
                                                        "uptime", "-p"],
          repr(fake.calls))
    check("plain run stdout pure", out == "", repr(out))


def test_run_dashdash_stripped():
    fake = FakeRun()
    do_run(run_args("plain", ["--", "ls", "-l"]), fake)
    check("leading -- stripped",
          fake.calls[0]["argv"][-2:] == ["ls", "-l"], repr(fake.calls))


def test_run_empty_command_like_connect():
    fake_run, fake_conn = FakeRun(), FakeRun()
    do_run(run_args("plain", []), fake_run)
    do_run(run_args("plain", [], cmd="connect"), fake_conn)
    check("empty command == connect argv",
          fake_run.calls[0]["argv"] == fake_conn.calls[0]["argv"],
          repr((fake_run.calls, fake_conn.calls)))


def test_run_tail_conflict():
    fake = FakeRun()
    code, _, err = do_run(run_args("tail", ["uptime"]), fake)
    check("tail + command dies", code == 1 and not fake.calls, repr(code))
    check("conflict names the remote command",
          "remote command" in err and "echo hi" in err, repr(err))
    fake = FakeRun()
    code, _, _ = do_run(run_args("tail", []), fake)
    check("tail entry runs bare",
          code == 0 and fake.calls[0]["argv"][-2:] == ["echo", "hi"],
          repr(fake.calls))


def test_run_tunnel_forward_conflict():
    fake = FakeRun()
    code, _, err = do_run(run_args("plain", ["uptime"],
                                   tunnel_forward="2222:127.0.0.1:22"), fake)
    check("-N + command dies", code == 1 and not fake.calls, repr(code))
    check("conflict explains -N", "tunnel-forward" in err, repr(err))


def test_run_exit_code():
    fake = FakeRun(rc=42)
    code, _, _ = do_run(run_args("plain", ["false"]), fake)
    check("exit code is ssh's", code == 42, repr(code))


def test_run_dry_reroute():
    fake = FakeRun()
    code, out, err = do_run(run_args("plain", ["uptime"]), fake, dry=True)
    check("run dry exits clean, ssh untouched",
          code is None and not fake.calls, repr((code, fake.calls)))
    check("run dry JSON on stderr, stdout pure",
          out == "" and '"dryRun": true' in err
          and '"uptime"' in err, repr((out, err)))
    code, out, err = do_run(run_args("plain", ["uptime"], cmd="connect"),
                            fake, dry=True)
    check("connect dry still on stdout",
          '"dryRun": true' in out, repr((out, err)))


def test_run_stdout_purity_vault():
    saved = mock_vault()
    try:
        fake = FakeRun()
        code, out, _ = do_run(run_args("vaulted", ["hostname"]), fake)
        check("vaulted run exit 0", code == 0, repr(code))
        check("vaulted run stdout pure", out == "", repr(out))
        check("vaulted argv carries key + command",
              "-i" in fake.calls[0]["argv"]
              and fake.calls[0]["argv"][-1] == "hostname",
              repr(fake.calls))
    finally:
        unmock_vault(saved)


def test_rebuild_keeps_command():
    argv = ["ssh", "-i", "k", "-J", "j", "dest.example", "df", "-h"]
    out = wtssh.rebuild_target_argv(argv, "<config>")
    check("rendered argv keeps command after block",
          out is not None and out[-3:] == ["wtssh-target", "df", "-h"]
          and "-i" not in out and "-J" not in out, repr(out))


def test_agent_legacy_carries_command():
    pub = TMP / "k1.pub"
    pub.write_text("ssh-ed25519 AAAA wtssh:k1\n", encoding="ascii")
    argv = ["ssh", "-i", "wtv:key1", "u@h9.example", "hostname", "-f"]
    refs = wtssh.argv_key_refs(argv)
    check("fixture refs resolve", len(refs) == 1 and refs[0][1] == "key1",
          repr(refs))
    fake = FakeRun()
    saved = wtssh.subprocess.run
    wtssh.subprocess.run = fake
    args = run_args("vaulted", ["hostname", "-f"])
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            wtssh.connect_agent_legacy(args, argv, refs, {"key1": str(pub)})
    except SystemExit:
        pass
    finally:
        wtssh.subprocess.run = saved
    check("agent-legacy argv swaps key, keeps command",
          fake.calls[0]["argv"] == ["ssh", "-o", "IdentitiesOnly=yes",
                                    "-i", str(pub), "u@h9.example",
                                    "hostname", "-f"],
          repr(fake.calls))


def test_secret_identity_unaffected():
    saved = (wtssh.secret_load, wtssh.subprocess.run, wtssh.probe_host_keys,
             wtssh.sweep_orphan_keydirs, wtssh.sweep_orphan_rundirs,
             wtssh.ssh_askpass_support)
    wtssh.secret_load = lambda name, ctx: "LOGINPW"
    fake = FakeRun()
    wtssh.subprocess.run = fake
    wtssh.probe_host_keys = lambda dests, strict=True: None
    wtssh.sweep_orphan_keydirs = lambda *a, **k: None
    wtssh.sweep_orphan_rundirs = lambda *a, **k: None
    wtssh.ssh_askpass_support = lambda: (True, "OpenSSH 9.9")
    try:
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                wtssh.action_connect(run_args("pwlogin", ["whoami"]))
        except SystemExit as e:
            code = e.code
    finally:
        (wtssh.secret_load, wtssh.subprocess.run, wtssh.probe_host_keys,
         wtssh.sweep_orphan_keydirs, wtssh.sweep_orphan_rundirs,
         wtssh.ssh_askpass_support) = saved
    check("secret run exit 0", code == 0, repr(code))
    check("secret run stdout pure", out.getvalue() == "",
          repr(out.getvalue()))
    check("secret argv appends command",
          fake.calls[0]["argv"][-2:] == ["bob@h5.example", "whoami"],
          repr(fake.calls))
    check("secret login identity from stored fields, not the command",
          fake.calls[0]["map"]["login"]["identities"] == ["bob@h5.example"],
          repr(fake.calls[0]["map"]))


def test_main_bare_routes_to_run():
    seen = {}
    saved = wtssh.action_connect
    wtssh.action_connect = lambda a: seen.update(vars(a))
    try:
        wtssh.main(["plain", "uptime", "-p"])
    finally:
        wtssh.action_connect = saved
    check("main routes bare NAME to run with command",
          seen.get("name") == "plain" and seen.get("command") == ["uptime", "-p"]
          and seen.get("cmd") == "run", repr(seen))
    seen.clear()
    wtssh.action_connect = lambda a: seen.update(vars(a))
    try:
        wtssh.main(["run", "plain", "--", "uptime"])
    finally:
        wtssh.action_connect = saved
    check("main explicit run keeps working",
          seen.get("name") == "plain" and seen.get("command") == ["uptime"],
          repr(seen))


def main():
    setup_env()
    test_bare_rewrite()
    test_run_parser()
    test_run_appends_command()
    test_run_dashdash_stripped()
    test_run_empty_command_like_connect()
    test_run_tail_conflict()
    test_run_tunnel_forward_conflict()
    test_run_exit_code()
    test_run_dry_reroute()
    test_run_stdout_purity_vault()
    test_rebuild_keeps_command()
    test_agent_legacy_carries_command()
    test_secret_identity_unaffected()
    test_main_bare_routes_to_run()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} -> {FAILURES}")
        return 1
    print("all run tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
