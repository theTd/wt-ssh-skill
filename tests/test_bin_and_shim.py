"""Offline drill tests for two Windows wiring fixes (no agent service, no
TPM, no PIN, no live config):

  1. native-OpenSSH resolution: ssh/ssh-add/ssh-keygen never resolve to an
     MSYS2/Cygwin build (those use $SSH_AUTH_SOCK, not the Windows agent
     named pipe), the family comes from one native suite, and find_bin's
     security properties survive (absolute honoured verbatim, explicit
     relative refused, CWD excluded, no bare-name degrade). The no-agent
     hint and the agent-load / auto-stage failures name the ssh-add binary
     that was used.
  2. launcher-shim self-heal: an existing shim whose interpreter or
     wtssh.py is gone is rewritten on ANY invocation; a shim whose targets
     still exist is left byte-identical (two live copies must not flip it);
     a missing shim is never created by a read-only invocation.

Run:  python tests/test_bin_and_shim.py
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

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-bin-shim-"))
FAILURES: list[str] = []

SSH3 = ("ssh.exe", "ssh-add.exe", "ssh-keygen.exe")
PATH_NAMES = ("ssh", "ssh-add", "ssh-keygen")


def check(name, cond, detail=""):
    """Unlike the older drills this RAISES on failure: under bare pytest a
    printed FAIL is invisible (the test still counts as passed), so a check
    that cannot fail the run is not a test."""
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)
        raise AssertionError(f"{name}: {detail}")


def setup_env():
    os.environ["WTSSH_RUN_DIR"] = str(TMP / "run")
    os.environ["WTSSH_SHIM_DIR"] = str(TMP / "shim")
    os.environ["WTSSH_AUDIT_DIR"] = str(TMP / "log")
    os.environ["WTSSH_AGENT_DIR"] = str(TMP / "agent")
    os.environ["WTSSH_NO_HOSTKEY_PROBE"] = "1"
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    wtssh.AGENT_DIR = TMP / "agent"
    for d in (wtssh.KEYS_DIR, wtssh.SECRETS_DIR, wtssh.AGENT_DIR,
              TMP / "run", TMP / "shim", TMP / "log"):
        d.mkdir(parents=True, exist_ok=True)
    (wtssh.KEYS_DIR / "k1.wtv").write_bytes(b"x")
    (TMP / "settings.json").write_text(
        json.dumps({"profiles": {"list": []}}), encoding="utf-8")
    wtssh._suite_dir_cache.clear()


# ------------------------------------------------------------- bin fixtures

def bin_dir(tag, *names, dll=None):
    """A fake install dir (tag may carry subdirs, e.g. 'git/usr/bin')."""
    d = TMP / "bins" / tag
    d.mkdir(parents=True, exist_ok=True)
    for name in names:
        (d / name).write_bytes(b"")
    if dll:
        (d / dll).write_bytes(b"")
    return d


def win_root(*rels, tag="winroot"):
    """A fake %SystemRoot% tree; each rel is a file created under it."""
    root = TMP / tag
    for rel in rels:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"")
    return root


def use_path(dirs, *, system_root=None):
    os.environ["PATH"] = os.pathsep.join(str(d) for d in dirs)
    if system_root is not None:
        os.environ["SystemRoot"] = str(system_root)
    wtssh._suite_dir_cache.clear()


def same(got, want):
    return got is not None and os.path.normcase(str(got)) == os.path.normcase(
        str(want))


# ------------------------------------------- native OpenSSH family resolution

def test_msys_dll_build_is_skipped():
    print("[bin: an MSYS build with the runtime DLL next to it is skipped]")
    msys = bin_dir("msys64/bin", *SSH3, dll="msys-2.0.dll")
    native = bin_dir("openssh", *SSH3)
    use_path([msys, native], system_root=win_root())
    for name in PATH_NAMES:
        got = wtssh.find_bin(name)
        check(f"{name} skips the MSYS build", same(got, native / f"{name}.exe"),
              repr(got))


def test_usr_bin_layout_is_skipped():
    print("[bin: Git-for-Windows' usr\\bin layout is skipped even without a DLL]")
    git = bin_dir("git/usr/bin", *SSH3)
    native = bin_dir("openssh-layout", *SSH3)
    use_path([git, native], system_root=win_root())
    for name in PATH_NAMES:
        got = wtssh.find_bin(name)
        check(f"{name} skips usr\\bin", same(got, native / f"{name}.exe"),
              repr(got))


def test_only_msys_falls_back_to_the_system32_anchor():
    print("[bin: no native PATH hit -> the System32 anchor, never the MSYS build]")
    git = bin_dir("git-anchor/usr/bin", *SSH3, dll="msys-2.0.dll")
    root = win_root(*[f"System32/OpenSSH/{n}" for n in SSH3],
                    tag="winroot-anchor")
    use_path([git], system_root=root)
    for name in PATH_NAMES:
        got = wtssh.find_bin(name)
        check(f"{name} lands on the anchor",
              same(got, root / "System32/OpenSSH" / f"{name}.exe"), repr(got))


def test_family_resolves_from_one_native_suite():
    print("[bin: all three members come from one native suite]")
    git = bin_dir("git-suite/usr/bin", *SSH3, dll="msys-2.0.dll")
    solo = bin_dir("solo", "ssh-add.exe")  # native, but EARLIER on PATH
    suite = bin_dir("suite", *SSH3)
    use_path([git, solo, suite], system_root=win_root())
    for name in PATH_NAMES:
        got = wtssh.find_bin(name)
        check(f"{name} from the suite", same(got, suite / f"{name}.exe"),
              repr(got))
    check("the suite beats an earlier standalone ssh-add",
          same(wtssh.find_bin("ssh-add"), suite / "ssh-add.exe"),
          repr(wtssh.find_bin("ssh-add")))


def test_native_openssh_outside_system32_is_acceptable():
    print("[bin: a native OpenSSH elsewhere on PATH is acceptable]")
    native = bin_dir("Program Files/OpenSSH", *SSH3)
    root = win_root(*[f"System32/OpenSSH/{n}" for n in SSH3],
                    tag="winroot-native")
    use_path([native], system_root=root)
    for name in PATH_NAMES:
        got = wtssh.find_bin(name)
        check(f"{name} honours the PATH build", same(got, native / f"{name}.exe"),
              repr(got))


def test_find_bin_security_properties_survive():
    print("[bin: find_bin security properties unchanged]")
    git = bin_dir("git-sec/usr/bin", *SSH3, dll="msys-2.0.dll")
    native = bin_dir("openssh-sec", *SSH3)
    use_path([git, native], system_root=win_root())
    check("an absolute MSYS name is honoured verbatim",
          same(wtssh.find_bin(str(git / "ssh-add.exe")), git / "ssh-add.exe"),
          repr(wtssh.find_bin(str(git / "ssh-add.exe"))))
    check("an explicit relative form is refused",
          wtssh.find_bin("git-sec/usr/bin/ssh-add.exe") is None,
          repr(wtssh.find_bin("git-sec/usr/bin/ssh-add.exe")))
    check("a dot-slash form is refused",
          wtssh.find_bin("./ssh-add.exe") is None,
          repr(wtssh.find_bin("./ssh-add.exe")))
    cwd = TMP / "cwd"
    cwd.mkdir(exist_ok=True)
    for name in SSH3:
        (cwd / name).write_bytes(b"")
    old = os.getcwd()
    os.chdir(cwd)
    try:
        use_path([cwd, native], system_root=win_root())
        for name in PATH_NAMES:
            got = wtssh.find_bin(name)
            check(f"the CWD hit is excluded ({name})",
                  same(got, native / f"{name}.exe"), repr(got))
    finally:
        os.chdir(old)
    use_path([], system_root=win_root(tag="winroot-empty"))
    check("a miss never degrades to a bare name", wtssh.find_bin("ssh") is None,
          repr(wtssh.find_bin("ssh")))


# ------------------------------------------------- agent failure diagnostics

def fake_ssh_add(tag="diagbin"):
    fake = TMP / tag / "ssh-add.exe"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_bytes(b"")
    return fake


def test_no_agent_hint_names_the_ssh_add():
    print("[agent: the no-agent hint names the ssh-add that was used]")
    fake = fake_ssh_add()
    saved_find, saved_add = wtssh.find_bin, wtssh._run_ssh_add
    wtssh.find_bin = lambda n: str(fake) if n == "ssh-add" else saved_find(n)
    wtssh._run_ssh_add = lambda argv: types.SimpleNamespace(
        returncode=2, stdout="",
        stderr="Could not open a connection to your authentication agent.")
    try:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_status(types.SimpleNamespace())
    finally:
        wtssh.find_bin, wtssh._run_ssh_add = saved_find, saved_add
    body = json.loads(out.getvalue())
    check("status still says no-agent", body["agent"] == "no-agent", body)
    check("status carries the ssh-add path",
          same(body.get("sshAdd"), fake), body)
    check("hint names the binary and keeps the Start-Service advice",
          str(fake) in body["hint"] and "Start-Service ssh-agent" in body["hint"],
          body["hint"])


def test_auto_stage_warning_names_the_ssh_add():
    print("[agent: the auto-stage refusal names the ssh-add that refused]")
    fake = fake_ssh_add("diagbin-stage")
    saved = (wtssh.find_bin, wtssh._run_ssh_add, wtssh.agent_key_material,
             wtssh.secure_mkkey)
    keydir = TMP / "stagekey"
    keydir.mkdir(exist_ok=True)
    (keydir / "key").write_bytes(b"container")
    wtssh.find_bin = lambda n: str(fake) if n == "ssh-add" else saved[0](n)
    wtssh.agent_key_material = lambda data, pw: (
        b"ssh-ed25519 AAAA wtssh\n", b"-----BEGIN OPENSSH PRIVATE KEY-----")
    wtssh.secure_mkkey = lambda data, cleartext=False: (keydir, keydir / "key")
    wtssh._run_ssh_add = lambda argv: types.SimpleNamespace(
        returncode=1, stdout="",
        stderr="Could not open a connection to your authentication agent.")
    try:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            staged = wtssh.agent_stage_unlocked({"k1": (b"junk", "")},
                                                source="drill")
    finally:
        (wtssh.find_bin, wtssh._run_ssh_add, wtssh.agent_key_material,
         wtssh.secure_mkkey) = saved
    text = err.getvalue()
    check("nothing staged", staged == [], repr(staged))
    check("warning keeps the agent symptom",
          "refused it" in text and "Could not open" in text, text)
    check("warning names the binary", str(fake) in text, text)


def test_agent_load_failure_names_the_ssh_add():
    print("[agent: an agent-load failure names the ssh-add in its reason]")
    fake = fake_ssh_add("diagbin-load")
    saved = (wtssh.find_bin, wtssh._run_ssh_add, wtssh.agent_key_material,
             wtssh.secure_mkkey, wtssh._chain_unlock_keys)
    keydir = TMP / "loadkey"
    keydir.mkdir(exist_ok=True)
    (keydir / "key").write_bytes(b"container")
    wtssh.find_bin = lambda n: str(fake) if n == "ssh-add" else saved[0](n)
    wtssh._chain_unlock_keys = lambda *a, **k: {"k1": (b"junk", "")}
    wtssh.agent_key_material = lambda data, pw: (
        b"ssh-ed25519 AAAA wtssh\n", b"-----BEGIN OPENSSH PRIVATE KEY-----")
    wtssh.secure_mkkey = lambda data, cleartext=False: (keydir, keydir / "key")
    wtssh._run_ssh_add = lambda argv: types.SimpleNamespace(
        returncode=1, stdout="",
        stderr="Could not open a connection to your authentication agent.")
    out = io.StringIO()
    code = None
    try:
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            wtssh.action_agent_load(types.SimpleNamespace(keys=["k1"], ttl=None))
    except SystemExit as e:
        code = e.code
    finally:
        (wtssh.find_bin, wtssh._run_ssh_add, wtssh.agent_key_material,
         wtssh.secure_mkkey, wtssh._chain_unlock_keys) = saved
    body = json.loads(out.getvalue())
    check("load reports failure", code == 1 and body["loaded"] == [], body)
    reason = body["failed"][0]["reason"] if body.get("failed") else ""
    check("failure reason names the binary", str(fake) in reason, reason)


# --------------------------------------------------------- launcher shim

def shim_file() -> Path:
    return wtssh.shim_path()


def write_shim(python: str, script: str, body: bytes | None = None) -> Path:
    s = shim_file()
    s.parent.mkdir(parents=True, exist_ok=True)
    if body is None:
        body = f'@echo off\r\n"{python}" "{script}" %*\r\n'.encode("utf-8")
    s.write_bytes(body)
    return s


def run_cli(argv):
    """One real wtssh invocation: argparse, globals, heal, dispatch."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        wtssh.main(list(argv))
    return out.getvalue(), err.getvalue()


def canon():
    """The exact launcher body the current interpreter + script imply."""
    return wtssh._shim_body().decode("utf-8")


def test_shim_dir_is_respected():
    print("[shim: WTSSH_SHIM_DIR decides where the launcher lives]")
    check("shim path follows the env hook",
          same(wtssh.shim_path(),
               Path(os.environ["WTSSH_SHIM_DIR"]) / "wtssh.cmd"),
          repr(wtssh.shim_path()))


def test_read_path_never_creates_the_shim():
    print("[shim: a read-only invocation never creates a missing shim]")
    s = shim_file()
    if s.exists():
        s.unlink()
    run_cli(["list"])
    check("list left no shim behind", not s.exists(), repr(str(s)))


def test_dead_script_is_healed_on_a_read_path():
    print("[shim: a shim pointing at a moved wtssh.py is rewritten]")
    s = write_shim(sys.executable, str(TMP / "moved-skill" / "wtssh.py"))
    run_cli(["list"])
    # decode the BYTES: read_text() would translate the CRLF line endings
    body = s.read_bytes().decode("utf-8")
    check("rewritten to the canonical body", body == canon(), repr(body))
    check("body names this script and interpreter",
          os.path.normcase(str(wtssh.SCRIPTS / "wtssh.py"))
          in os.path.normcase(body)
          and os.path.normcase(sys.executable) in os.path.normcase(body),
          repr(body))


def test_dead_interpreter_is_healed_on_a_read_path():
    print("[shim: a shim whose interpreter is gone is rewritten]")
    s = write_shim(str(TMP / "gone-python" / "python.exe"),
                   str(wtssh.SCRIPTS / "wtssh.py"))
    run_cli(["list"])
    check("rewritten to the canonical body", s.read_bytes() == wtssh._shim_body(),
          repr(s.read_text(encoding="utf-8")))


def test_live_shim_is_never_rewritten():
    print("[shim: a shim naming another LIVE copy is left byte-identical]")
    other_script = TMP / "copyB" / "scripts" / "wtssh.py"
    other_script.parent.mkdir(parents=True, exist_ok=True)
    other_script.write_text("# another live copy\n", encoding="utf-8")
    other_python = TMP / "copyB" / "python.exe"
    other_python.write_bytes(b"")
    s = write_shim(str(other_python), str(other_script))
    before = s.read_bytes()
    run_cli(["list"])
    check("untouched after a read path", s.read_bytes() == before,
          repr(s.read_text(encoding="utf-8")))


def test_unusable_bodies_and_foreign_launchers():
    print("[shim: an unusable body is repaired, a foreign launcher is left]")
    s = write_shim("", "", body=b"@echo off\r\n")
    run_cli(["list"])
    check("a body with no program is repaired", s.read_bytes() == wtssh._shim_body(),
          repr(s.read_text(encoding="utf-8")))
    foreign = b'@echo off\r\n"C:\\tools\\mine.exe" %*\r\n'
    s.write_bytes(foreign)
    run_cli(["list"])
    check("a launcher naming no wtssh.py is not ours to rewrite",
          s.read_bytes() == foreign, repr(s.read_text(encoding="utf-8")))
    s.write_bytes(b'@echo off\r\n"python.exe" "scripts\\wtssh.py" %*\r\n')
    run_cli(["list"])
    check("a relative launcher is rewritten", s.read_bytes() == wtssh._shim_body(),
          repr(s.read_text(encoding="utf-8")))


def test_write_path_still_creates_the_shim():
    print("[shim: write operations still create/repair the launcher]")
    s = shim_file()
    if s.exists():
        s.unlink()
    wtssh.ensure_shim()
    check("ensure_shim creates the canonical body",
          s.read_bytes() == wtssh._shim_body(),
          repr(s.read_text(encoding="utf-8")))
    s.write_bytes(b'@echo off\r\n"C:\\gone\\python.exe" '
                  b'"C:\\gone\\wtssh.py" %*\r\n')
    wtssh.ensure_shim()
    check("ensure_shim repairs a dead launcher",
          s.read_bytes() == wtssh._shim_body(),
          repr(s.read_text(encoding="utf-8")))


TESTS = (
    test_msys_dll_build_is_skipped,
    test_usr_bin_layout_is_skipped,
    test_only_msys_falls_back_to_the_system32_anchor,
    test_family_resolves_from_one_native_suite,
    test_native_openssh_outside_system32_is_acceptable,
    test_find_bin_security_properties_survive,
    test_no_agent_hint_names_the_ssh_add,
    test_auto_stage_warning_names_the_ssh_add,
    test_agent_load_failure_names_the_ssh_add,
    test_shim_dir_is_respected,
    test_read_path_never_creates_the_shim,
    test_dead_script_is_healed_on_a_read_path,
    test_dead_interpreter_is_healed_on_a_read_path,
    test_live_shim_is_never_rewritten,
    test_unusable_bodies_and_foreign_launchers,
    test_write_path_still_creates_the_shim,
)


def main():
    setup_env()
    for fn in TESTS:
        try:
            fn()
        except AssertionError as e:
            print(f"\nFAILED: {e}")
            return 1
    print("\nall bin/shim tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
