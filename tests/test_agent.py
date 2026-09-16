"""Offline drill tests for the ssh-agent cache (no TPM, no real agent, no
writes to the live settings/vault):

  1. TTL parsing (suffixes, bare seconds, env default, garbage dies).
  2. Key material: cryptography re-serialization of real ssh-keygen keys
     (encrypted + plain) -- pub matches `ssh-keygen -lf`, wrong
     passphrase raises ValueError.
  3. Coverage decisions (records + live fingerprint, hermetic when empty).
  4. `agent load` wiring (mocked unlock + ssh-add): unencrypted temp,
     pub selector persisted, temp wiped, per-key failures collected.
  5. `agent unload` / `status` shapes.
  6. Connect branches (rendered + legacy single-key): pub-selector config
     / argv, no containers, no dispatcher env, no unlock call.
  7. print --plan carries the offline `agentCached` hint.

Run:  python tests/test_agent.py
"""
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-agent-"))
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
    os.environ["WTSSH_AGENT_DIR"] = str(TMP / "agent")
    os.environ.pop("WTSSH_AGENT_TTL", None)
    os.environ.pop("WTSSH_NO_AGENT", None)
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    wtssh.AGENT_DIR = TMP / "agent"
    for d in (wtssh.KEYS_DIR, wtssh.SECRETS_DIR, wtssh.AGENT_DIR,
              TMP / "run", TMP / "shim", TMP / "log"):
        d.mkdir(parents=True, exist_ok=True)
    (wtssh.KEYS_DIR / "k1.wtv").write_bytes(b"x")
    (wtssh.KEYS_DIR / "k2.wtv").write_bytes(b"x")
    (TMP / "settings.json").write_text(json.dumps({
        "profiles": {"list": [
            {"name": "ssh:single",
             "guid": "{bbbbbbbb-0000-0000-0000-000000000001}",
             "commandline": "ssh -i wtv:k1 u@h1.example",
             "hidden": False},
            {"name": "ssh:jumper",
             "guid": "{bbbbbbbb-0000-0000-0000-000000000002}",
             "commandline": "ssh -i wtv:k2 j@hop.example",
             "hidden": True},
            {"name": "ssh:via",
             "guid": "{bbbbbbbb-0000-0000-0000-000000000003}",
             "commandline": "ssh -i wtv:k1 -J jumper u@h2.example",
             "hidden": False},
        ]}}), encoding="utf-8")


def dies(fn, *a, **k):
    try:
        fn(*a, **k)
    except SystemExit:
        return True
    return False


# ---------------------------------------------------------------- TTL

def ttl_tests():
    print("[agent: ttl]")
    secs, label = wtssh.parse_agent_ttl("8h")
    check("8h -> 28800", secs == 28800 and label == "8h", repr((secs, label)))
    check("90m", wtssh.parse_agent_ttl("90m")[0] == 5400)
    check("bare seconds", wtssh.parse_agent_ttl("60")[0] == 60)
    check("combined 1h30m", wtssh.parse_agent_ttl("1h30m")[0] == 5400)
    check("cap 90d ok", wtssh.parse_agent_ttl("90d")[0] == 90 * 86400)
    check("over cap dies", dies(wtssh.parse_agent_ttl, "91d"))
    check("over cap dies (weeks)", dies(wtssh.parse_agent_ttl, "9999w"))
    check("default 8h", wtssh.parse_agent_ttl(None)[0] == 28800)
    os.environ["WTSSH_AGENT_TTL"] = "30m"
    try:
        check("env default", wtssh.parse_agent_ttl(None)[0] == 1800)
    finally:
        os.environ.pop("WTSSH_AGENT_TTL", None)
    for bad in ("", "0", "abc", "8x", "-5", "h"):
        check(f"reject {bad!r}", dies(wtssh.parse_agent_ttl, bad))
    # the load path renders this template with (name, dest, keys) only --
    # a stray placeholder would KeyError on the real (unstubbed) path
    for lang in ("zh", "en"):
        os.environ["WTSSH_UI_LANG"] = lang
        try:
            ctx = wtssh.pin_text("pin_agent_load", name="ssh-agent",
                                 dest="8h", keys="k1, k2")
            check(f"pin template renders ({lang})",
                  "8h" in ctx and "k1, k2" in ctx, ctx)
        finally:
            os.environ.pop("WTSSH_UI_LANG", None)


# ------------------------------------------------- crypto (real keys, offline)

KEYGEN = wtssh.find_bin("ssh-keygen")


def gen_key(name, passphrase):
    priv = TMP / name
    if priv.exists():
        priv.unlink()
    if (TMP / f"{name}.pub").exists():
        (TMP / f"{name}.pub").unlink()
    args = ["ssh-keygen", "-t", "ed25519", "-f", str(priv), "-N",
            passphrase, "-C", name, "-q"]
    r = subprocess.run([KEYGEN] + args[1:], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    return priv.read_bytes()


def crypto_tests():
    print("[agent: key material]")
    if KEYGEN is None:
        print("  SKIP ssh-keygen missing")
        return
    plain = gen_key("plain", "")
    enc = gen_key("enc", "s3cret-pw")
    pub, clear = wtssh.agent_key_material(enc, "s3cret-pw")
    check("pub is one openssh line",
          pub.startswith(b"ssh-ed25519 ") and pub.endswith(b"\n"), repr(pub[:40]))
    check("container is unencrypted openssh",
          clear.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
          repr(clear[:40]))
    # fingerprint agrees with ssh-keygen on the derived pub (no passphrase
    # needed for a .pub, so this stays fully offline)
    pubfile = TMP / "derived.pub"
    pubfile.write_bytes(pub)
    r = subprocess.run([KEYGEN, "-lf", str(pubfile)], capture_output=True,
                       text=True, timeout=60)
    check("ssh-keygen reads derived pub", r.returncode == 0, r.stderr)
    check("fp matches ssh-keygen",
          r.stdout.split()[1] == wtssh.agent_fp_of_pub(pub), r.stdout)
    pub2, _ = wtssh.agent_key_material(plain, "")
    check("plain key loads with empty pw", pub2.startswith(b"ssh-ed25519 "))
    check("wrong passphrase -> ValueError",
          _raises_valueerror(enc, "nope"))
    check("missing password -> ValueError",
          _raises_valueerror(enc, ""))


def _raises_valueerror(keydata, pw):
    try:
        wtssh.agent_key_material(keydata, pw)
    except ValueError:
        return True
    return False


# ------------------------------------------------------- coverage decisions

def seed_records(fp_by_key, ttl=28800):
    import time as _time
    now = int(_time.time())
    recs = {k: {"fp": fp, "ttl": ttl, "enforcement": "wtssh",
                "loaded_at": now, "expires_at": now + ttl}
            for k, fp in fp_by_key.items()}
    wtssh.agent_save_records(recs)
    for k in fp_by_key:
        wtssh.agent_pub_path(k).write_text("ssh-ed25519 AAAA wtssh\n",
                                           encoding="ascii")


def coverage_tests():
    print("[agent: coverage]")
    saved = wtssh.agent_list_live
    try:
        wtssh.agent_list_live = lambda strict=True: ("ok", {"SHA256:AAA": "c1"})
        check("empty keys -> None", wtssh.agent_coverage([]) is None)
        check("no records -> None", wtssh.agent_coverage(["k1"]) is None)
        seed_records({"k1": "SHA256:AAA"})
        check("covered", wtssh.agent_coverage(["k1"]) == {"k1": str(
            wtssh.agent_pub_path("k1"))})
        check("missing key -> None",
              wtssh.agent_coverage(["k1", "k2"]) is None)
        seed_records({"k1": "SHA256:ZZZ"})
        check("stale fp -> None", wtssh.agent_coverage(["k1"]) is None)
        wtssh.agent_list_live = lambda strict=True: ("no-agent", {})
        seed_records({"k1": "SHA256:AAA"})
        check("no agent -> None", wtssh.agent_coverage(["k1"]) is None)
        # expiry is client-side: a past-due record is uncovered AND the
        # key is best-effort unloaded
        unloads = []
        saved_add = wtssh._run_ssh_add
        wtssh._run_ssh_add = lambda argv: (
            unloads.append(list(argv)),
            types.SimpleNamespace(returncode=0, stdout="",
                                  stderr=""))[1]
        wtssh.agent_save_records(
            {"k9": {"fp": "SHA256:AAA", "ttl": 60, "enforcement": "wtssh",
                    "loaded_at": 1, "expires_at": 2}})
        wtssh.agent_pub_path("k9").write_text("ssh-ed25519 AAAA wtssh\n",
                                              encoding="ascii")
        wtssh.agent_list_live = lambda strict=True: ("ok", {"SHA256:AAA": "c1"})
        check("expired record -> None",
              wtssh.agent_coverage(["k9"]) is None)
        check("expired key best-effort unloaded",
              unloads == [["-d", str(wtssh.agent_pub_path("k9"))]],
              unloads)
        wtssh._run_ssh_add = saved_add
        # F2: a missing/malformed expires_at is expired, never "forever"
        wtssh.agent_save_records(
            {"kx": {"fp": "SHA256:AAA", "ttl": 60, "loaded_at": 1},
             "ky": {"fp": "SHA256:AAA", "ttl": 60, "loaded_at": 1,
                    "expires_at": "soon"}})
        for k in ("kx", "ky"):
            wtssh.agent_pub_path(k).write_text("ssh-ed25519 AAAA wtssh\n",
                                               encoding="ascii")
        check("missing expires_at -> None",
              wtssh.agent_coverage(["kx"]) is None)
        check("malformed expires_at -> None",
              wtssh.agent_coverage(["ky"]) is None)
        # agent weirdness must never kill a connect: strict=False swallows
        # unknown output, strict (status) stays loud. Restore the REAL
        # function first -- the stubs above would mask it.
        wtssh.agent_list_live = saved
        wtssh._run_ssh_add = lambda argv: types.SimpleNamespace(
            returncode=99, stdout="", stderr="weird")
        try:
            check("strict dies on weird output",
                  dies(wtssh.agent_list_live))
            check("non-strict swallows",
                  wtssh.agent_list_live(strict=False) == ("unknown", {}))
            seed_records({"k1": "SHA256:AAA"})
            check("coverage survives weird agent",
                  wtssh.agent_coverage(["k1"]) is None)
        finally:
            wtssh._run_ssh_add = saved_add
    finally:
        wtssh.agent_list_live = saved
    # hermetic: no records must not spawn any subprocess
    for f in wtssh.AGENT_DIR.glob("*"):
        f.unlink()
    saved_run = wtssh._run_ssh_add
    try:
        def _boom(argv):
            raise AssertionError("_run_ssh_add must not run")
        wtssh._run_ssh_add = _boom
        check("empty cache spawns nothing",
              wtssh.agent_coverage(["k1"]) is None)
    finally:
        wtssh._run_ssh_add = saved_run


# ------------------------------------------------------------- agent load

class FakeAdd:
    def __init__(self):
        self.calls = []
        self.paths = {}

    def __call__(self, argv):
        self.calls.append(list(argv))
        if len(argv) == 1:
            # the unconstrained add: argv is just the temp container
            self.paths[argv[0]] = Path(argv[0]).read_bytes()
        elif argv and argv[0] == "-t":
            self.paths[argv[-1]] = Path(argv[-1]).read_bytes()
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def load_tests():
    print("[agent: load]")
    if KEYGEN is None:
        print("  SKIP ssh-keygen missing")
        return
    enc = gen_key("loadkey", "pw-pw")
    saved_unlock = wtssh._chain_unlock_keys
    saved_add = wtssh._run_ssh_add
    saved_live = wtssh.agent_list_live
    saved_mkkey = wtssh.secure_mkkey
    saved_material = wtssh.agent_key_material
    fake = FakeAdd()
    made = []
    pub, _ = wtssh.agent_key_material(enc, "pw-pw")
    fp = wtssh.agent_fp_of_pub(pub)

    def fake_mkkey(data, cleartext=False):
        assert cleartext is True  # load always stages cleartext (see below)
        d = Path(tempfile.mkdtemp(prefix="wtssh-key-"))
        (d / "key").write_bytes(data)
        made.append(d)
        return d, d / "key"

    wtssh._chain_unlock_keys = lambda *a, **k: {"k1": (enc, "pw-pw")}
    wtssh._run_ssh_add = fake
    wtssh.agent_list_live = lambda strict=True: ("ok", {fp: "loadkey"})
    wtssh.secure_mkkey = fake_mkkey
    try:
        args = types.SimpleNamespace(keys=["k1"], ttl="1h")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_load(args)
        body = json.loads(out.getvalue())
        check("load ok", body["ok"] and body["loaded"] == ["k1"], body)
        check("ttl label", body["ttl"] == "1h", body)
        check("client-side enforcement marker",
              body.get("enforcement") == "wtssh", body)
        check("ssh-add without -t (service refuses lifetimes)",
              fake.calls and len(fake.calls[0]) == 1
              and fake.calls[0][0].endswith("key"), fake.calls)
        check("temp held cleartext",
              list(fake.paths.values())[0].startswith(
                  b"-----BEGIN OPENSSH PRIVATE KEY-----"))
        check("temp wiped", not made[0].exists())
        check("pub selector persisted",
              wtssh.agent_pub_path("k1").read_bytes().splitlines()[0] == pub.strip())
        check("record persisted",
              wtssh.agent_load_records()["k1"]["fp"] == fp)
        # per-key failure does not kill the batch
        wtssh._chain_unlock_keys = lambda *a, **k: {
            "k1": (enc, "pw-pw"), "k2": (b"junk", "")}
        fake2 = FakeAdd()
        wtssh._run_ssh_add = fake2
        out2 = io.StringIO()
        rc = 0
        try:
            with redirect_stdout(out2), redirect_stderr(io.StringIO()):
                wtssh.action_agent_load(
                    types.SimpleNamespace(keys=["k1", "k2"], ttl=None))
        except SystemExit as e:
            rc = e.code
        body2 = json.loads(out2.getvalue())
        check("batch survives one bad key",
              rc == 1 and body2["loaded"] == ["k1"]
              and [f["key"] for f in body2["failed"]] == ["k2"], body2)
        # F1: a non-ValueError from material must not escape the batch
        wtssh.agent_key_material = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("weird backend failure"))
        wtssh._chain_unlock_keys = lambda *a, **k: {
            "k1": (enc, "pw-pw"), "k2": (enc, "pw-pw")}
        out3 = io.StringIO()
        rc3 = 0
        try:
            with redirect_stdout(out3), redirect_stderr(io.StringIO()):
                wtssh.action_agent_load(
                    types.SimpleNamespace(keys=["k1", "k2"], ttl=None))
        except SystemExit as e:
            rc3 = e.code
        body3 = json.loads(out3.getvalue())
        check("non-ValueError stays per-key",
              rc3 == 1 and body3["loaded"] == []
              and sorted(f["key"] for f in body3["failed"]) == ["k1", "k2"]
              and all("weird backend" in f["reason"]
                      for f in body3["failed"]), body3)
    finally:
        wtssh._chain_unlock_keys = saved_unlock
        wtssh._run_ssh_add = saved_add
        wtssh.agent_list_live = saved_live
        wtssh.secure_mkkey = saved_mkkey
        wtssh.agent_key_material = saved_material


# --------------------------------------------------- unload / status

def unload_status_tests():
    print("[agent: unload/status]")
    fp = "SHA256:AAA"
    seed_records({"k1": fp, "k2": "SHA256:BBB"})
    saved_add = wtssh._run_ssh_add
    saved_live = wtssh.agent_list_live
    calls = []
    wtssh._run_ssh_add = lambda argv: (
        calls.append(list(argv)),
        types.SimpleNamespace(returncode=0, stdout="", stderr=""))[1]
    wtssh.agent_list_live = lambda strict=True: ("ok", {fp: "c1"})
    try:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_unload(types.SimpleNamespace(keys=[], all=False))
        body = json.loads(out.getvalue())
        check("unload defaults to live-tracked only",
              body["unloaded"] == ["k1"], body)
        check("ssh-add -d by pub",
              calls == [["-d", str(wtssh.agent_pub_path("k1"))]], calls)
        check("record dropped + pub deleted",
              "k1" not in wtssh.agent_load_records()
              and not wtssh.agent_pub_path("k1").exists())
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_status(types.SimpleNamespace())
        st = json.loads(out.getvalue())
        check("status shape",
              st["agent"] == "ok" and len(st["keys"]) == 1
              and st["keys"][0]["key"] == "k2"
              and st["keys"][0]["live"] is False, st)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_unload(types.SimpleNamespace(keys=[], all=True))
        body = json.loads(out.getvalue())
        check("--all flushes + clears",
              body["all"] and wtssh.agent_load_records() == {}, body)
        check("-D issued", calls[-1] == ["-D"], calls)
        # F6: default unload includes tracked-but-expired keys
        past = int(__import__("time").time()) - 10
        wtssh.agent_save_records(
            {"kx": {"fp": "SHA256:AAA", "ttl": 60, "loaded_at": 1,
                    "expires_at": past}})
        wtssh.agent_pub_path("kx").write_text("ssh-ed25519 AAAA wtssh\n",
                                              encoding="ascii")
        wtssh.agent_list_live = lambda strict=True: ("ok", {})
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_unload(types.SimpleNamespace(keys=[], all=False))
        body = json.loads(out.getvalue())
        check("default unload takes expired-tracked",
              body["unloaded"] == ["kx"], body)
        # F3: unreachable agent never traces back, records kept
        wtssh.agent_save_records(
            {"kz": {"fp": "SHA256:AAA", "ttl": 60, "loaded_at": 1,
                    "expires_at": past + 10 ** 9}})
        wtssh.agent_pub_path("kz").write_text("ssh-ed25519 AAAA wtssh\n",
                                              encoding="ascii")
        wtssh.agent_list_live = lambda strict=True: ("no-agent", {})
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            wtssh.action_agent_unload(types.SimpleNamespace(keys=[], all=False))
        body = json.loads(out.getvalue())
        check("unreachable agent keeps records",
              body["unloaded"] == [] and "kz" in wtssh.agent_load_records()
              and "unreachable" in err.getvalue(), body)
        def _raise(argv):
            raise OSError("nope")
        wtssh._run_ssh_add = _raise
        out = io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                wtssh.action_agent_unload(types.SimpleNamespace(keys=["kz"],
                                                                all=False))
        except SystemExit:
            pass  # failed entries exit 1 by design
        body = json.loads(out.getvalue())
        check("explicit unload survives OSError",
              body["failed"] and body["failed"][0]["key"] == "kz"
              and "kz" in wtssh.agent_load_records(), body)
    finally:
        wtssh._run_ssh_add = saved_add
        wtssh.agent_list_live = saved_live


# ------------------------------------------------------- connect branches

class FakeRun:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, env=None, **kw):
        entry = {"argv": list(argv), "env": dict(env or {}),
                 "config": None}
        if "-F" in argv:
            cfg = Path(argv[argv.index("-F") + 1])
            if cfg.exists():
                entry["config"] = cfg.read_text(encoding="utf-8")
        self.calls.append(entry)
        return types.SimpleNamespace(returncode=0)


def _plan_single():
    return {"keys": ["k1"], "argv": ["ssh"],
            "blocks": [{"block": "wtssh-target", "entry": "single",
                        "name": "single", "user": "u", "host": "h1.example",
                        "port": None,
                        "identities": [{"kind": "keyref", "key": "k1"}]}]}


def connect_branch_tests():
    print("[agent: connect branches]")
    saved_run = wtssh.subprocess.run
    saved_probe = wtssh.probe_host_keys
    saved_live = wtssh.agent_list_live
    saved_unlock = wtssh._chain_unlock_keys
    fake = FakeRun()
    wtssh.subprocess.run = fake
    wtssh.probe_host_keys = lambda dests, strict=True: None
    fp = "SHA256:AAA"
    seed_records({"k1": fp})
    wtssh.agent_list_live = lambda strict=True: ("ok", {fp: "c1"})
    wtssh._chain_unlock_keys = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("PIN path must not run when agent covers"))
    try:
        # rendered branch: pub-selector config, no dispatcher
        plan = _plan_single()
        pubs = {"k1": str(wtssh.agent_pub_path("k1"))}
        p = {"name": "ssh:single", "commandline": "ssh -i wtv:k1 u@h1.example"}
        args = types.SimpleNamespace(name="single", extra=[],
                                     tunnel_forward=None, no_askpass=False,
                                     no_agent=False)
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                wtssh.connect_agent_rendered(
                    args, p, ["ssh", "-i", "wtv:k1", "u@h1.example"],
                    plan, pubs)
        except SystemExit as e:
            check("rendered exits 0", e.code == 0, e.code)
        argv = fake.calls[-1]["argv"]
        check("rendered argv -F target, no -i",
              "-F" in argv and "wtssh-target" in argv
              and "-i" not in argv, argv)
        cfg = fake.calls[-1]["config"] or ""
        check("rendered config selects pub",
              f'IdentityFile "{pubs["k1"]}"' in cfg, cfg)
        check("rendered config keeps IdentitiesOnly",
              "IdentitiesOnly yes" in cfg, cfg)
        check("rendered config has no PA hardening",
              "PasswordAuthentication" not in cfg, cfg)
        check("rendered env has no dispatcher",
              "SSH_ASKPASS" not in fake.calls[-1]["env"]
              and "WTSSH_ASKPASS_MAP" not in fake.calls[-1]["env"])
        # legacy branch: -i swap only in the option region
        argv_in = ["ssh", "-i", "wtv:k1", "u@h1.example", "grep", "-i",
                   "wtv:k1"]
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                wtssh.connect_agent_legacy(
                    args, argv_in, [(None, "k1")], pubs)
        except SystemExit as e:
            check("legacy exits 0", e.code == 0, e.code)
        out_argv = fake.calls[-1]["argv"]
        check("legacy swaps option -i only",
              out_argv == ["ssh", "-o", "IdentitiesOnly=yes",
                           "-i", pubs["k1"], "u@h1.example", "grep",
                           "-i", "wtv:k1"], out_argv)
        # F5: a hand-mangled `-i wtv:` (valid prefix, invalid spelling)
        # rides verbatim, exactly like the PIN path's rewrite_key_arg
        argv_bad = ["ssh", "-i", "wtv:k1", "-i", "wtv:", "u@h1.example"]
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                wtssh.connect_agent_legacy(
                    args, argv_bad, [(None, "k1")], pubs)
        except SystemExit:
            pass
        out_bad = fake.calls[-1]["argv"]
        check("mangled wtv: kept verbatim",
              out_bad == ["ssh", "-o", "IdentitiesOnly=yes",
                          "-i", pubs["k1"], "-i", "wtv:",
                          "u@h1.example"], out_bad)
        # F9d: agent branches scrub every askpass carrier from the child env
        os.environ["SSH_ASKPASS"] = "C:\\evil\\ask.cmd"
        os.environ["WTSSH_ASKPASS_MAP"] = str(TMP / "stale-map.json")
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                try:
                    wtssh.connect_agent_legacy(
                        args, argv_in, [(None, "k1")], pubs)
                except SystemExit:
                    pass
        finally:
            os.environ.pop("SSH_ASKPASS", None)
            os.environ.pop("WTSSH_ASKPASS_MAP", None)
        scrubbed = fake.calls[-1]["env"]
        check("agent env carries no askpass",
              "SSH_ASKPASS" not in scrubbed
              and "WTSSH_ASKPASS_MAP" not in scrubbed
              and "WTSSH_PASSPHRASE" not in scrubbed, scrubbed)
        # full action_connect prefers the agent branch (no PIN call)
        fake.calls.clear()
        args2 = types.SimpleNamespace(name="single", extra=[],
                                      tunnel_forward=None, no_askpass=False,
                                      no_agent=False)
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                wtssh.action_connect(args2)
        except SystemExit:
            pass
        check("connect takes agent branch",
              fake.calls and "-F" not in fake.calls[-1]["argv"]
              and pubs["k1"] in fake.calls[-1]["argv"], fake.calls)
        # --no-agent forces the PIN path (unlock stub raises)
        args3 = types.SimpleNamespace(name="single", extra=[],
                                      tunnel_forward=None, no_askpass=False,
                                      no_agent=True)
        saved_payload = wtssh.vault_open_payload
        wtssh._chain_unlock_keys = lambda *a, **k: (_ for _ in ()).throw(
            SystemExit(99))
        wtssh.vault_open_payload = lambda *a, **k: (_ for _ in ()).throw(
            SystemExit(99))
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                wtssh.action_connect(args3)
        except SystemExit as e:
            check("--no-agent reaches PIN path", e.code == 99, e.code)
        # WTSSH_NO_AGENT env forces the PIN path like --no-agent
        # (payload stub still active: both must reach the PIN read)
        os.environ["WTSSH_NO_AGENT"] = "1"
        try:
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                wtssh.action_connect(args2)
        except SystemExit as e:
            check("WTSSH_NO_AGENT reaches PIN path", e.code == 99, e.code)
        finally:
            os.environ.pop("WTSSH_NO_AGENT", None)
            wtssh.vault_open_payload = saved_payload
    finally:
        wtssh.subprocess.run = saved_run
        wtssh.probe_host_keys = saved_probe
        wtssh.agent_list_live = saved_live
        wtssh._chain_unlock_keys = saved_unlock


# --------------------------------------------------------------- print hint

def print_hint_tests():
    print("[agent: print hint]")
    for f in wtssh.AGENT_DIR.glob("*"):
        f.unlink()
    plan = _plan_single()
    check("no cache -> empty hint",
          wtssh.plan_public(plan, None)["agentCached"] == [])
    seed_records({"k1": "SHA256:AAA"})
    got = wtssh.plan_public(plan, None)
    check("cached key listed", got["agentCached"] == ["k1"], got)
    check("legacy shape keeps hint",
          wtssh.plan_public(None, "r")["agentCached"] == [])


def main():
    setup_env()
    ttl_tests()
    crypto_tests()
    coverage_tests()
    load_tests()
    unload_status_tests()
    connect_branch_tests()
    print_hint_tests()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall agent tests passed")


if __name__ == "__main__":
    main()
