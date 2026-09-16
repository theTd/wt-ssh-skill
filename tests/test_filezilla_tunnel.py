"""Offline drill tests for the single-PIN FileZilla tunnel (no vault,
no real ssh, no writes to the live settings / site list / vault /
filezilla.xml):

  1. rendered connect through the extracted helpers: ONE unwrap-many
     gesture, map schema v2, -F + PA=no argv, opaque target block,
     session dirs wiped afterwards (connect_rendered equivalence guard).
  2. dry-run contract unchanged: no vault touch, "mapEntries": 0.
  3. filezilla --tunnel merged path (SOCKS): the FileZilla session-key
     export and the whole jump chain share ONE unwrap-many; the parent
     spawns the tunnel ssh itself (`-N -D <private port>`, destination =
     the LAST HOP block -- dials originate at the same vantage as -J) with
     a hop-keys-only askpass map; the site keeps the entry's REAL
     host:port (BypassProxy pinned to 0); FileZilla's generic proxy is
     pointed at the AUTHENTICATED gate (per-session user/password, the
     -D port never leaves the parent) and restored once the launched
     FileZilla instance exits; everything is wiped when the tunnel exits.
  4. filezilla --tunnel fallback (chain cannot render): the parent keeps
     the -L shape -- its own export gesture + a child connect spawn with
     drilled env and no stale WTSSH_RENDER_DRY; the site stays rewritten
     to 127.0.0.1:<port>, BypassProxy pinned to 1, no generic-proxy
     write, "proxy": null in the JSON.
  4b. jump-free vault entry under --tunnel auto: no SOCKS / no proxy write,
     ONE pin_filezilla_export gesture, sessionKey.mode=direct-vault,
     ephemeral PPK wiped when FileZilla exits; --no-open stays ask.
  5. filezilla.xml generic-proxy apply/restore roundtrip: exact five-key
     snapshot semantics, absent-key removal, FTP Proxy keys untouched.

Run:  python tests/test_filezilla_tunnel.py
"""
import base64
import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import types
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-"))
FAILURES: list[str] = []

FZ_XML_FIXTURE = """<?xml version="1.0"?>
<FileZilla3 version="3.69.5" platform="windows">
\t<Settings>
\t\t<Setting name="Use Pasv mode">1</Setting>
\t\t<Setting name="FTP Proxy type">0</Setting>
\t\t<Setting name="Proxy host">9.9.9.9</Setting>
\t\t<Setting name="Proxy port">1080</Setting>
\t\t<Setting name="Proxy user">u1</Setting>
\t\t<Setting name="Proxy password">p1</Setting>
\t\t<Setting name="Proxy type">0</Setting>
\t</Settings>
</FileZilla3>
"""


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


@contextlib.contextmanager
def overrides(**patches):
    saved = [(k, getattr(wtssh, k)) for k in patches]
    try:
        for k, v in patches.items():
            setattr(wtssh, k, v)
        yield
    finally:
        for k, v in saved:
            setattr(wtssh, k, v)


@contextlib.contextmanager
def subprocess_overrides(run=None, popen=None):
    saved_run = wtssh.subprocess.run
    saved_popen = wtssh.subprocess.Popen
    try:
        if run is not None:
            wtssh.subprocess.run = run
        if popen is not None:
            wtssh.subprocess.Popen = popen
        yield
    finally:
        wtssh.subprocess.run = saved_run
        wtssh.subprocess.Popen = saved_popen


class FakeRun:
    """subprocess.run stand-in: stashes argv/env and the mid-flight map
    file (the real wipe happens only after this returns)."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, env=None, **kw):
        entry = {"argv": list(argv), "env": dict(env or {}), "map": None}
        mp = (env or {}).get("WTSSH_ASKPASS_MAP")
        if mp and Path(mp).exists():
            entry["map"] = json.loads(Path(mp).read_text(encoding="utf-8"))
        self.calls.append(entry)
        return types.SimpleNamespace(returncode=0)


class FakePopen:
    """subprocess.Popen stand-in: records every spawn, snapshotting the
    mid-flight askpass map (the parent wipes the run dir only after
    wait()); the fake process stays alive until wait()ed (exit 0).
    wait() must accept the timeout kwarg: the tunnel is waited with
    wait(timeout=5) and FileZilla with wait(timeout=0.5) polling."""

    SEQ = 0   # per-instance pid counter (the socks gate reads .pid)

    def __init__(self):
        self.calls = []

    def __call__(self, argv, env=None, **kw):
        entry = {"argv": list(argv), "env": dict(env or {}), "map": None}
        mp = (env or {}).get("WTSSH_ASKPASS_MAP")
        if mp and Path(mp).exists():
            entry["map"] = json.loads(Path(mp).read_text(encoding="utf-8"))
        self.calls.append(entry)
        FakePopen.SEQ += 1
        return types.SimpleNamespace(poll=lambda: None,
                                     wait=lambda timeout=None: 0,
                                     terminate=lambda: None,
                                     kill=lambda: None, returncode=0,
                                     # the socks gate's private-port
                                     # ownership check reads tunnel_proc.pid
                                     pid=4000 + FakePopen.SEQ)


class VaultFake:
    """Records every unlock gesture; answers with distinct key material."""

    def __init__(self):
        self.loaded = []   # phase-1 envelope reads ("key '<name>'")
        self.unwraps = []  # (batch size, use context)
        self.opens = []    # (keyname, use context, dek pre-supplied?)

    def load_blob(self, raw, what, want):
        self.loaded.append(what)
        return {"v": 2, "alg": "AES-256-GCM", "name": want,
                "nonce": "", "wdek": base64.b64encode(b"d").decode(),
                "ct": ""}

    def unwrap_many(self, wrapped, use_context):
        self.unwraps.append((len(wrapped), use_context))
        return [b"d"] * len(wrapped)

    def open_payload(self, kind, name, raw, what, ctx, dek=None):
        self.opens.append((name, ctx, dek is not None))
        return {"fmt": 4, "name": name,
                "key": base64.b64encode(
                    b"container-" + name.encode()).decode(),
                "passphrase": "PW-" + name}


class MkKeyFake:
    """secure_mkkey stand-in: real dirs under TMP so the wipe assertions
    can check they are gone."""

    def __init__(self):
        self.dirs = []
        self.i = 0

    def __call__(self, keydata):
        self.i += 1
        d = TMP / f"keydir{self.i}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "key").write_bytes(keydata)
        self.dirs.append(d)
        return d, d / "key"


def setup_env():
    os.environ["WTSSH_RUN_DIR"] = str(TMP / "run")
    os.environ["WTSSH_SHIM_DIR"] = str(TMP / "shim")
    os.environ["WTSSH_AUDIT_DIR"] = str(TMP / "log")
    os.environ["WTSSH_NO_HOSTKEY_PROBE"] = "1"
    os.environ["WTSSH_FZ_SITEMANAGER"] = str(TMP / "sitemanager.xml")
    os.environ["WTSSH_FZ_FILEZILLAXML"] = str(TMP / "filezilla.xml")
    os.environ.pop("WTSSH_RENDER_DRY", None)
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    for d in (wtssh.SECRETS_DIR, wtssh.KEYS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    for k in ("key1", "key2"):
        (wtssh.KEYS_DIR / f"{k}.wtv").write_bytes(b"x")
    (TMP / "sitemanager.xml").write_text(
        '<?xml version="1.0"?><FileZilla3><Servers /></FileZilla3>',
        encoding="utf-8")
    (TMP / "filezilla.xml").write_text(FZ_XML_FIXTURE, encoding="utf-8")


def write_settings(entries):
    (TMP / "settings.json").write_text(json.dumps(
        {"profiles": {"list": entries}}), encoding="utf-8")


CHAIN_ENTRIES = [
    {"name": "ssh:jump1", "guid": "{aaaaaaaa-0000-0000-0000-000000000001}",
     "commandline": "ssh -i wtv:key1 u1@j1.example", "hidden": True},
    {"name": "ssh:target", "guid": "{aaaaaaaa-0000-0000-0000-000000000002}",
     "commandline": "ssh -i wtv:key2 -J jump1 u2@t2.example"},
]
POISONED_ENTRIES = [
    {"name": "ssh:jump1", "guid": "{aaaaaaaa-0000-0000-0000-000000000003}",
     "commandline": "ssh -i wtv:key1 -o ServerAliveInterval=30 "
                    "u1@j1.example", "hidden": True},
    {"name": "ssh:target", "guid": "{aaaaaaaa-0000-0000-0000-000000000004}",
     "commandline": "ssh -i wtv:key2 -J jump1 u2@t2.example"},
]


def run_connect(name, **kw):
    fake = FakeRun()
    args = types.SimpleNamespace(name=name, extra=[], tunnel_forward=None,
                                 no_askpass=False)
    out, err = io.StringIO(), io.StringIO()
    with subprocess_overrides(run=fake):
        try:
            with redirect_stdout(out), redirect_stderr(err):
                wtssh.action_connect(args)
        except SystemExit:
            pass  # action_connect ends with sys.exit(rc) on the happy path
    return fake, out.getvalue(), err.getvalue()


def test_rendered_connect():
    print("[rendered connect via helpers]")
    write_settings(CHAIN_ENTRIES)
    vault, mkkey = VaultFake(), MkKeyFake()
    with overrides(vault_load_blob=vault.load_blob,
                   vault_unwrap_many=vault.unwrap_many,
                   vault_open_payload=vault.open_payload,
                   secure_mkkey=mkkey):
        fake, _, _ = run_connect("target")
    check("exactly ONE unwrap-many gesture", len(vault.unwraps) == 1,
          repr(vault.unwraps))
    check("batch covers the whole chain (2 keys)",
          vault.unwraps and vault.unwraps[0][0] == 2, repr(vault.unwraps))
    check("every prompt answered from the pre-unlocked DEKs",
          all(given for _n, _c, given in vault.opens), repr(vault.opens))
    call = fake.calls[0]
    argv, env = call["argv"], call["env"]
    check("argv carries -F", "-F" in argv, repr(argv))
    check("PA=no hardening before -F",
          "PasswordAuthentication=no" in argv
          and argv.index("PasswordAuthentication=no") < argv.index("-F"),
          repr(argv))
    check("destination is the opaque target block",
          argv[-1] == wtssh.BLOCK_TARGET, repr(argv))
    check("map is schema v2, login empty",
          call["map"] is not None
          and call["map"]["v"] == wtssh.MAP_SCHEMA_VERSION
          and call["map"]["login"] is None, repr(call["map"]))
    check("map registers both containers one-shot",
          call["map"] is not None
          and sorted(e["uses"] for e in call["map"]["keys"].values())
          == [1, 1], repr(call["map"]))
    check("env NEVER carries WTSSH_PASSPHRASE",
          "WTSSH_PASSPHRASE" not in env
          and "WTSSH_PASSPHRASE" not in " ".join(argv))
    check("dispatcher wired", env.get("SSH_ASKPASS_REQUIRE") == "force")
    check("session dirs wiped after connect",
          all(not d.exists() for d in mkkey.dirs)
          and not any((TMP / "run").glob("wtssh-run-*")
                      if (TMP / "run").exists() else []))


def test_dry_run():
    print("[dry-run contract unchanged]")
    write_settings(CHAIN_ENTRIES)
    vault = VaultFake()
    os.environ["WTSSH_RENDER_DRY"] = "1"
    try:
        with overrides(vault_load_blob=vault.load_blob,
                       vault_unwrap_many=vault.unwrap_many,
                       vault_open_payload=vault.open_payload):
            _, out, _ = run_connect("target")
        data = json.loads(out)
        check("dry: flag + no vault gesture",
              data.get("dryRun") is True and vault.unwraps == []
              and vault.opens == [], repr(vault.unwraps))
        check("dry: mapEntries 0", data.get("mapEntries") == 0, repr(data))
        check("dry: config rendered for the whole chain",
              data.get("config", "").count("Host ") == 2, repr(data)[:200])
    finally:
        os.environ.pop("WTSSH_RENDER_DRY", None)


def run_filezilla(name, tunnel, entries, extra=None):
    """Run `wtssh filezilla NAME [--tunnel]` fully faked; returns
    (result-json|None, FakePopen, clip texts, MkKeyFake, VaultFake, raised).
    Binds a real loopback listener so the port-wait loop succeeds
    instantly. `extra` folds additional monkeypatches (failure drills);
    a raised SystemExit/OSError/... is captured into `raised`."""
    write_settings(entries)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)
    vault, mkkey, popen = VaultFake(), MkKeyFake(), FakePopen()
    clip: list[str] = []

    def copy(text):
        clip.append(text)
        return True

    picks: list[int] = []

    def pick_port():
        # 1st call = the tunnel's PRIVATE listener -> the pre-bound fake
        # listener port, so the readiness poll succeeds instantly; later
        # calls are gate material (merged path only) -> fresh ephemeral
        # ports the gate can really bind and hold
        if not picks:
            picks.append(port)
            return port
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        picks.append(p)
        return p

    patches = dict(fz_pick_port=pick_port,
                   filezilla_exe=lambda a: str(TMP / "fz-fake.exe"),
                   copy_to_clipboard=copy,
                   ppk_export_bytes=lambda container, old, new, comment:
                       b"session-key-material",
                   vault_load_blob=vault.load_blob,
                   vault_unwrap_many=vault.unwrap_many,
                   vault_open_payload=vault.open_payload,
                   secure_mkkey=mkkey)
    if extra:
        patches.update(extra)
    args = types.SimpleNamespace(name=name, keyfile=None, no_open=False,
                                 remove_site=False, tunnel=tunnel,
                                 filezilla=None)
    raised = None
    try:
        with overrides(**patches):
            with subprocess_overrides(popen=popen):
                out, _err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(_err):
                    wtssh.action_filezilla(args)
        result = json.loads(out.getvalue())
    except BaseException as e:
        raised = e
        result = None
    finally:
        srv.close()
    return result, popen, clip, mkkey, vault, raised


def fz_proxy_settings():
    """The five generic-proxy keys as a dict, parsed from the drilled
    filezilla.xml copy (Setting elements live under <Settings>)."""
    root = ET.parse(TMP / "filezilla.xml").getroot()
    out = {}
    for key in wtssh.FZ_PROXY_KEYS:
        el = root.find(f'Settings/Setting[@name="{key}"]')
        out[key] = None if el is None else (el.text or "")
    return out


def test_filezilla_merged():
    print("[filezilla --tunnel merged single-PIN SOCKS path]")
    real_apply = wtssh.fz_proxy_apply
    applied: list[tuple] = []

    def spy_apply(port, user, password):
        # F1 guard: the merged run must aim FileZilla at the PUBLIC gate
        # port with THIS session's credentials -- a private-port or
        # swapped-credential regression must fail here, not in production
        applied.append((port, user, password))
        return real_apply(port, user, password)

    result, popen, clip, mkkey, vault, raised = run_filezilla(
        "target", True, CHAIN_ENTRIES, extra={"fz_proxy_apply": spy_apply})
    check("happy path raises nothing", raised is None, repr(raised))
    check("export + chain share ONE unwrap-many",
          len(vault.unwraps) == 1 and vault.unwraps[0][0] == 2,
          repr(vault.unwraps))
    check("both keys pre-unlocked (dek handed to open)",
          len(vault.opens) == 2
          and all(given for _n, _c, given in vault.opens),
          repr(vault.opens))
    check("single PIN window is context-named for both purposes",
          all("FileZilla" in ctx for _n, ctx, _g in vault.opens),
          repr([ctx for _n, ctx, _g in vault.opens]))
    check("no child connect spawned (ssh + FileZilla only)",
          len(popen.calls) == 2, repr([c["argv"][:3] for c in popen.calls]))
    ssh_call = popen.calls[0]
    fz_call = popen.calls[1]
    argv, env = ssh_call["argv"], ssh_call["env"]
    check("ssh argv carries -N -D PRIVATE listener (no -L)",
          "-N" in argv and "-D" in argv
          and "-L" not in argv, repr(argv))
    d_spec = argv[argv.index("-D") + 1]
    check("-D pins the bind address to 127.0.0.1 (GatewayPorts-proof)",
          d_spec.startswith("127.0.0.1:")
          and d_spec.split(":", 1)[1].isdigit(), repr(d_spec))
    priv_port = int(d_spec.split(":", 1)[1])
    check("gate fronting: FileZilla's port is NOT ssh's -D port",
          priv_port != result["tunnel"]["localPort"],
          repr((priv_port, result["tunnel"]["localPort"])))
    check("entry -p stripped from the tunnel argv", "-p" not in argv,
          repr(argv))
    check("ssh argv carries -F + PA=no",
          "-F" in argv and "PasswordAuthentication=no" in argv, repr(argv))
    check("ssh destination is the LAST HOP block (not the target)",
          argv[-1] == "wtssh-hop-1" and wtssh.BLOCK_TARGET not in argv,
          repr(argv))
    check("ssh env dispatches from the map, never a passphrase env",
          env.get("SSH_ASKPASS_REQUIRE") == "force"
          and bool(env.get("WTSSH_ASKPASS_MAP"))
          and "WTSSH_PASSPHRASE" not in env, repr(sorted(env)))
    mp = ssh_call["map"]
    check("askpass map is v2, login empty, HOP keys only",
          mp is not None and mp["v"] == wtssh.MAP_SCHEMA_VERSION
          and mp["login"] is None and len(mp["keys"]) == 1
          and all(e["pw"] == "PW-key1" and e["uses"] == 1
                  for e in mp["keys"].values()),
          repr(mp))
    check("FileZilla opened at the wtssh site path",
          fz_argv := [c for c in popen.calls
                      if c["argv"][0].endswith("fz-fake.exe")],
          repr([c["argv"] for c in popen.calls]))
    check("filezilla -c targets the group folder site",
          fz_call["argv"] == [str(TMP / "fz-fake.exe"), "-c",
                              "0/ssh/target"], repr(fz_call["argv"]))
    check("site synced: real address + session keyfile + key logon",
          result["auth"]["logontype"] == "key"
          and result["auth"]["keyfileSource"] == "session-ppk2"
          and "fz-target-key" in result["auth"]["keyfile"],
          repr(result["auth"]))
    site = (TMP / "sitemanager.xml").read_text(encoding="utf-8")
    check("site XML keeps the entry's REAL host:port (no 127.0.0.1)",
          "<Host>t2.example</Host>" in site and "<Port>22</Port>" in site
          and "<Host>127.0.0.1</Host>" not in site, repr(site)[:200])
    check("site XML rides the proxy (BypassProxy pinned to 0)",
          "<BypassProxy>0</BypassProxy>" in site, repr(site)[:200])
    check("mode is socks-last-hop with an authenticated socks5 proxy URL",
          result["tunnel"]["mode"] == "socks-last-hop"
          and result["tunnel"]["proxy"]
          == f"socks5://127.0.0.1:{result['tunnel']['localPort']}"
          and result["tunnel"]["proxyAuth"] is True,
          repr(result["tunnel"]))
    check("tunnel JSON shape fixed (no credential fields ride stdout)",
          set(result["tunnel"]) == {"mode", "localPort", "proxy",
                                    "proxyAuth", "siteEndpoint",
                                    "pinPrompts"}, repr(result["tunnel"]))
    check("generic proxy aimed at the PUBLIC port + session credentials",
          len(applied) == 1
          and applied[0][0] == result["tunnel"]["localPort"]
          and applied[0][0] != priv_port
          and len(applied[0][1]) >= 16 and len(applied[0][2]) >= 16
          and applied[0][1] != applied[0][2]
          and applied[0][1] != "u1" and applied[0][2] != "p1",
          repr(applied))
    check("result reports ONE pin", result["tunnel"]["pinPrompts"] == 1,
          repr(result["tunnel"]))
    check("passphrase went to the clipboard only (piped stdout)",
          len(clip) == 1 and "passphrase" not in result
          and result["clipboard"] is True, repr(result.get("clipboard")))
    rundir = Path(result["auth"]["keyfile"]).parent
    check("run dir carries the fz- prefix (wiped-session recognition)",
          rundir.name.startswith("wtssh-run-fz-"), str(rundir))
    check("run dir wiped after the tunnel closed",
          not rundir.exists(), str(rundir))
    check("containers wiped after the tunnel closed",
          all(not d.exists() for d in mkkey.dirs)
          and not any((TMP / "run").glob("wtssh-run-fz-*")
                      if (TMP / "run").exists() else []))
    proxy = fz_proxy_settings()
    check("generic proxy restored to the pre-tunnel five keys",
          proxy == {"Proxy type": "0", "Proxy host": "9.9.9.9",
                    "Proxy port": "1080", "Proxy user": "u1",
                    "Proxy password": "p1"}, repr(proxy))
    check("generic-proxy backup written beside the settings",
          (TMP / "filezilla.xml.wtssh.bak").exists(),
          str(TMP / "filezilla.xml.wtssh.bak"))


def test_filezilla_fallback():
    print("[filezilla --tunnel fallback (chain cannot render)]")
    os.environ["WTSSH_RENDER_DRY"] = "1"  # must not leak into the child
    try:
        result, popen, clip, mkkey, vault, raised = run_filezilla(
            "target", True, POISONED_ENTRIES)
    finally:
        os.environ.pop("WTSSH_RENDER_DRY", None)
    check("happy path raises nothing", raised is None, repr(raised))
    check("parent does its own export gesture (no batch)",
          len(vault.opens) == 1 and vault.unwraps == []
          and "FileZilla" in vault.opens[0][1],
          repr((vault.unwraps, vault.opens)))
    check("export targets the entry's vault key",
          vault.opens[0][0] == "key2", repr(vault.opens))
    child = popen.calls[0]
    check("child connect spawned for the chain",
          child["argv"] == [sys.executable, str(SCRIPTS / "wtssh.py"),
                            "connect", "target", "--tunnel-forward",
                            f"{result['tunnel']['localPort']}:127.0.0.1:22"],
          repr(child["argv"]))
    check("child env drilled + never dry-runs",
          child["env"].get("WTSSH_SETTINGS") == str(wtssh.SETTINGS)
          and "WTSSH_RENDER_DRY" not in child["env"],
          repr(sorted(child["env"])))
    check("fallback reports the parent's export PIN only",
          result["tunnel"]["pinPrompts"] == 1, repr(result["tunnel"]))
    check("fallback mode: no socks proxy, no auth in the JSON",
          result["tunnel"]["mode"] == "forward-fallback"
          and result["tunnel"]["proxy"] is None
          and result["tunnel"]["proxyAuth"] is False, repr(result["tunnel"]))
    check("generic proxy NOT touched on the fallback path",
          fz_proxy_settings() == {"Proxy type": "0", "Proxy host": "9.9.9.9",
                                  "Proxy port": "1080", "Proxy user": "u1",
                                  "Proxy password": "p1"},
          repr(fz_proxy_settings()))
    check("session keyfile bound + wiped afterwards",
          result["auth"]["keyfileSource"] == "session-ppk2"
          and not Path(result["auth"]["keyfile"]).parent.exists(),
          repr(result["auth"]))
    site = (TMP / "sitemanager.xml").read_text(encoding="utf-8")
    check("fallback site stays endpoint-rewritten to 127.0.0.1:<port>",
          f"<Host>127.0.0.1</Host>" in site
          and f"<Port>{result['tunnel']['localPort']}</Port>" in site,
          repr(site)[:200])
    check("fallback site bypasses any user-level generic proxy",
          "<BypassProxy>1</BypassProxy>" in site, repr(site)[:200])


def test_filezilla_failure_cleanup():
    print("[filezilla --tunnel: failure paths wipe secrets]")
    # (a) mid-materialize die (the host-key probe refusal class): the
    #     containers self-clean inside _chain_materialize_run, the rundir
    #     (askpass map + config + session key) via the inner finally
    def boom_render(*a, **k):
        raise RuntimeError("render blew up")

    _, popen, _clip, mkkey, _vault, raised = run_filezilla(
        "target", True, CHAIN_ENTRIES, extra={"render_config": boom_render})
    check("materialize die propagates", isinstance(raised, RuntimeError),
          repr(raised))
    check("containers wiped on materialize die",
          mkkey.dirs and all(not d.exists() for d in mkkey.dirs),
          repr([str(d) for d in mkkey.dirs]))
    check("rundir wiped on materialize die",
          not any((TMP / "run").glob("wtssh-run-*")
                  if (TMP / "run").exists() else []))
    check("nothing spawned after a materialize die", popen.calls == [])

    # (b) site-sync die AFTER a full materialize: the outer finally wipes
    #     rundir + keydirs (the keydirs_clean flag must have survived)
    def boom_save(tree, path):
        raise OSError("site list unwritable")

    _, popen, _clip, mkkey, _vault, raised = run_filezilla(
        "target", True, CHAIN_ENTRIES, extra={"fz_save_tree": boom_save})
    check("site-sync die propagates", isinstance(raised, OSError),
          repr(raised))
    check("containers wiped after a sync die",
          mkkey.dirs and all(not d.exists() for d in mkkey.dirs),
          repr([str(d) for d in mkkey.dirs]))
    check("rundir wiped after a sync die",
          not any((TMP / "run").glob("wtssh-run-*")
                  if (TMP / "run").exists() else []))

    # (c) fallback export die: the empty session dir goes, too; the raw
    #     conversion failure is converted into a clean wtssh die
    #     (SystemExit) whose message points at re-importing the key
    def boom_ppk(*a, **k):
        raise RuntimeError("ppk export blew up")

    _, popen, _clip, mkkey, _vault, raised = run_filezilla(
        "target", True, POISONED_ENTRIES,
        extra={"ppk_export_bytes": boom_ppk})
    check("fallback export die propagates",
          isinstance(raised, SystemExit), repr(raised))
    check("no child spawned after a fallback export die", popen.calls == [])
    check("fallback rundir wiped",
          not any((TMP / "run").glob("wtssh-run-*")
                  if (TMP / "run").exists() else []))

    # (d) gate bind failure: die names the public port, the finally belt
    # reaps the already-spawned tunnel, and FileZilla never spawns (so no
    # generic-proxy write ever raced the failure)
    def boom_gate(pub_port, priv_port, user, password, tunnel_pid):
        raise OSError("cannot bind")

    _r, popen, _clip, _mkkey, _vault, raised = run_filezilla(
        "target", True, CHAIN_ENTRIES, extra={"socks_gate_serve": boom_gate})
    check("gate bind die propagates", isinstance(raised, SystemExit),
          repr(raised))
    check("gate bind die spawns only the tunnel (no FileZilla)",
          len(popen.calls) == 1, repr([c["argv"][:2] for c in popen.calls]))


def test_rendered_connect_failure():
    print("[rendered connect: materialize die wipes containers]")
    write_settings(CHAIN_ENTRIES)
    vault, mkkey = VaultFake(), MkKeyFake()

    def boom_render(*a, **k):
        raise RuntimeError("render blew up")

    raised = None
    with overrides(vault_load_blob=vault.load_blob,
                   vault_unwrap_many=vault.unwrap_many,
                   vault_open_payload=vault.open_payload,
                   secure_mkkey=mkkey,
                   render_config=boom_render):
        try:
            run_connect("target")
        except RuntimeError as e:  # the helper self-cleans, then re-raises
            raised = e
    check("connect materialize die propagates", raised is not None,
          repr(raised))
    check("connect containers wiped (helper self-clean covers both callers)",
          mkkey.dirs and all(not d.exists() for d in mkkey.dirs),
          repr([str(d) for d in mkkey.dirs]))
    check("connect run dir wiped by the function's own finally",
          not any((TMP / "run").glob("wtssh-run-*")
                  if (TMP / "run").exists() else []))


def test_proxy_config_roundtrip():
    print("[filezilla.xml generic-proxy apply/restore roundtrip]")
    cfg = TMP / "filezilla.xml"
    cfg.write_text(FZ_XML_FIXTURE, encoding="utf-8")
    saved = wtssh.fz_proxy_apply(54321, "gate-u", "gate-p")
    proxy = fz_proxy_settings()
    check("apply points the generic proxy at the authenticated SOCKS gate",
          proxy == {"Proxy type": "2", "Proxy host": "127.0.0.1",
                    "Proxy port": "54321", "Proxy user": "gate-u",
                    "Proxy password": "gate-p"}, repr(proxy))
    check("apply leaves the FTP proxy keys alone",
          ET.parse(cfg).getroot().findtext(
              'Settings/Setting[@name="FTP Proxy type"]') == "0", "")
    check("apply backs up the prior file",
          (TMP / "filezilla.xml.wtssh.bak").read_text(encoding="utf-8")
          == FZ_XML_FIXTURE, "")
    wtssh.fz_proxy_restore(saved)
    check("restore writes the five prior keys back verbatim",
          fz_proxy_settings() == {"Proxy type": "0", "Proxy host": "9.9.9.9",
                                  "Proxy port": "1080", "Proxy user": "u1",
                                  "Proxy password": "p1"},
          repr(fz_proxy_settings()))
    # a previously-ABSENT config: apply seeds, restore removes our keys
    cfg.unlink()
    bak = TMP / "filezilla.xml.wtssh.bak"
    bak.unlink(missing_ok=True)
    saved2 = wtssh.fz_proxy_apply(54322, "gate-u2", "gate-p2")
    seeded = fz_proxy_settings()
    check("apply seeds a missing filezilla.xml (type + credentials)",
          seeded["Proxy type"] == "2" and seeded["Proxy user"] == "gate-u2"
          and seeded["Proxy password"] == "gate-p2", repr(seeded))
    wtssh.fz_proxy_restore(saved2)
    root = ET.parse(cfg).getroot()
    leftovers = [k for k in wtssh.FZ_PROXY_KEYS
                 if root.find(f'Settings/Setting[@name="{k}"]') is not None]
    check("restore removes our keys from a previously-absent file",
          leftovers == [], repr(leftovers))


def test_ppk_v2_export():
    print("[PPK v2 export: PuTTY cryptsuite known-answer + self-check]")
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

    # testPPKLoadSave's encrypted PPK v2 ssh-ed25519 vector, lifted
    # verbatim from PuTTY's test/cryptsuite.py: the private blob is
    # 'AAAAIGvv...EBpY' (4-byte length + the 32-byte seed), the
    # passphrase is 'test-passphrase'. The builder must reproduce the
    # whole file byte-for-byte -- KDF, SHA-1-prefix padding, AES-256-CBC,
    # HMAC-SHA1 message, 64-column base64 wrapping and line counts.
    seed = base64.b64decode(
        "AAAAIGvvIpl8jyqn8Xufkw6v3FnEGtXF3KWw55AP3/AGEBpY")[4:]
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    expected = (
        "PuTTY-User-Key-File-2: ssh-ed25519\n"
        "Encryption: aes256-cbc\n"
        "Comment: ed25519-key-20200105\n"
        "Public-Lines: 2\n"
        "AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6F\n"
        "JH1W\n"
        "Private-Lines: 1\n"
        "4/jKlTgC652oa9HLVGrMjHZw7tj0sKRuZaJPOuLhGTvb25Jzpcqpbi+Uf+y+uo+Z\n"
        "Private-MAC: 5b1f6f4cc43eb0060d2c3e181bc0129343adba2b\n").encode()
    got = wtssh._build_ppk_v2(key, "test-passphrase",
                              "ed25519-key-20200105")
    check("PPK v2 vector byte-exact (PuTTY cryptsuite testPPKLoadSave)",
          got == expected,
          f"got {got[:200]!r}... vs expected {expected[:200]!r}...")

    # RSA goes through the same pipeline; the fail-closed self-check runs
    # on every build, so a clean return already proves parse/MAC parity
    rkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    text = wtssh._build_ppk_v2(rkey, "drill-pass", "rsa drill").decode(
        "ascii")
    check("RSA export builds with an ssh-rsa v2 header",
          text.startswith("PuTTY-User-Key-File-2: ssh-rsa\n"
                          "Encryption: aes256-cbc\n"
                          "Comment: rsa drill\n"), repr(text[:80]))

    # ECDSA P-256: the nistp256 curve name rides both the ssh_id and its
    # own string field
    etext = wtssh._build_ppk_v2(
        ec.generate_private_key(ec.SECP256R1()), "drill-pass",
        "ec drill").decode("ascii")
    check("ECDSA P-256 export builds with an ecdsa-sha2-nistp256 v2 header",
          etext.startswith("PuTTY-User-Key-File-2: ecdsa-sha2-nistp256\n"
                           "Encryption: aes256-cbc\n"
                           "Comment: ec drill\n"), repr(etext[:80]))

    dtext = wtssh._build_ppk_v2(
        dsa.generate_private_key(key_size=1024), "drill-pass",
        "dsa drill").decode("ascii")
    check("DSA export builds with an ssh-dss v2 header",
          dtext.startswith("PuTTY-User-Key-File-2: ssh-dss\n"
                           "Encryption: aes256-cbc\n"), repr(dtext[:60]))

    # SECP256K1 is a valid cryptography curve but has no PPK mapping
    raised = None
    try:
        wtssh._build_ppk_v2(ec.generate_private_key(ec.SECP256K1()),
                            "drill-pass", "unsupported curve")
    except SystemExit as e:
        raised = e
    check("unsupported curve dies cleanly", raised is not None,
          repr(raised))

    # tamper with the serialized MAC: the self-check must die, never hand
    # FileZilla a key it would reject at connect time
    tampered = bytearray(got)
    mark = tampered.rindex(b"Private-MAC: ") + len(b"Private-MAC: ")
    tampered[mark] = ord("0") if tampered[mark] != ord("0") else ord("1")
    raised = None
    try:
        wtssh._ppk_v2_selfcheck(bytes(tampered), "test-passphrase")
    except SystemExit as e:
        raised = e
    check("self-check dies on a tampered MAC", raised is not None,
          repr(raised))


def test_filezilla_direct_vault_export():
    print("[filezilla --tunnel auto: jump-free vault session-key export]")
    entries = [
        {"name": "ssh:example-host",
         "guid": "{aaaaaaaa-0000-0000-0000-000000000010}",
         "commandline": "ssh -i wtv:key2 -p 22 root@10.0.0.1"},
    ]
    (wtssh.KEYS_DIR / "key2.wtv").write_bytes(b"x")
    result, popen, clip, mkkey, vault, raised = run_filezilla(
        "example-host", "auto", entries)
    check("direct vault export succeeds", raised is None, repr(raised))
    check("tunnelAuto stays direct", result.get("tunnelAuto") == "direct",
          repr(result))
    check("no tunnel block", "tunnel" not in result, repr(result))
    check("sessionKey direct-vault",
          result.get("sessionKey", {}).get("mode") == "direct-vault"
          and result["sessionKey"].get("pinPrompts") == 1
          and result["sessionKey"].get("keyfileSource") == "session-ppk2",
          repr(result.get("sessionKey")))
    check("site bound to session key",
          result["auth"]["logontype"] == "key"
          and result["auth"]["keyfileSource"] == "session-ppk2"
          and "fz-example-host-key" in (result["auth"]["keyfile"] or ""),
          repr(result["auth"]))
    check("ONE open_payload export gesture (no unwrap-many)",
          len(vault.opens) == 1 and vault.unwraps == [],
          repr((vault.opens, vault.unwraps)))
    check("PIN context is pin_filezilla_export",
          vault.opens and "FileZilla" in vault.opens[0][1],
          repr(vault.opens))
    check("no SOCKS/proxy spawn beyond FileZilla",
          len(popen.calls) == 1
          and popen.calls[0]["argv"][0].endswith("fz-fake.exe"),
          repr(popen.calls))
    check("generic proxy untouched",
          fz_proxy_settings()["Proxy type"] == "0"
          and fz_proxy_settings()["Proxy host"] == "9.9.9.9",
          repr(fz_proxy_settings()))
    check("session key wiped after FileZilla exits",
          not Path(result["auth"]["keyfile"]).parent.exists(),
          repr(result["auth"]))
    check("passphrase delivered via clipboard",
          result.get("clipboard") is True and clip, repr(clip))

    # --no-open must NOT export: sync-only stays on ask/password
    write_settings(entries)
    args = types.SimpleNamespace(name="example-host", keyfile=None, no_open=True,
                                 remove_site=False, tunnel="auto",
                                 filezilla=None)
    vault2 = VaultFake()
    with overrides(vault_load_blob=vault2.load_blob,
                   vault_unwrap_many=vault2.unwrap_many,
                   vault_open_payload=vault2.open_payload,
                   filezilla_exe=lambda a: str(TMP / "fz-fake.exe"),
                   ppk_export_bytes=lambda *a, **k: b"x"):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            wtssh.action_filezilla(args)
    doc = json.loads(out.getvalue())
    check("auto --no-open stays ask (no session export)",
          doc["auth"]["logontype"] == "ask"
          and "sessionKey" not in doc
          and vault2.opens == [] and vault2.unwraps == [],
          repr((doc.get("auth"), vault2.opens)))
    check("auto --no-open still reports direct",
          doc.get("tunnelAuto") == "direct", repr(doc))

def main():
    setup_env()
    test_rendered_connect()
    test_dry_run()
    test_rendered_connect_failure()
    test_ppk_v2_export()
    test_filezilla_merged()
    test_filezilla_fallback()
    test_filezilla_failure_cleanup()
    test_filezilla_direct_vault_export()
    test_proxy_config_roundtrip()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} -> {FAILURES}")
        return 1
    print("all FileZilla-tunnel tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
