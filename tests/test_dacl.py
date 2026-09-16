"""Offline tests for the owner-only DACL path (no vault, no real ssh, no
writes outside a temp sandbox):

  1. real ctypes apply: a touched file/dir gets exactly the expected
     PROTECTED owner-only full-control DACL (read back via
     GetNamedSecurityInfoW + SD->SDDL, independent of the write path);
  2. fail-closed: an unavailable DACL mechanism raises DaclError; the
     explicit opt-out WTSSH_ALLOW_LOOSE_ACL=1 degrades to chmod + a
     ONE-TIME warning;
  3. no stranded partial dirs: make_run_dir / secure_mkkey remove their
     own shell when the DACL cannot land;
  4. propagation: secure_write surfaces DaclError (callers decide
     die vs warn); atomic_write_owner_only lands a protected file.

Run:  python tests/test_dacl.py
"""
import io
import os
import re
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

NT = os.name == "nt"
TMP = Path(tempfile.mkdtemp(prefix="wtssh-dacl-test-"))
FAILURES: list[str] = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


def skip(name):
    print(f"  skip {name} (not Windows)")


# --------------------------------------------------------------- SDDL readback

def read_sddl(path: Path) -> str:
    """Owner + DACL of `path` as an SDDL string -- an independent read
    path (GetNamedSecurityInfoW) so the assertion does not trust the
    writer's own machinery."""
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p))
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG))
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = \
        wintypes.BOOL
    k32.LocalFree.argtypes = (ctypes.c_void_p,)
    k32.LocalFree.restype = ctypes.c_void_p
    OWNER_SI, DACL_SI = 0x1, 0x4
    psid, pdacl, psd = (ctypes.c_void_p(), ctypes.c_void_p(),
                        ctypes.c_void_p())
    rc = adv.GetNamedSecurityInfoW(str(path), 1,  # SE_FILE_OBJECT
                                   OWNER_SI | DACL_SI,
                                   ctypes.byref(psid), None,
                                   ctypes.byref(pdacl), None,
                                   ctypes.byref(psd))
    assert rc == 0, f"GetNamedSecurityInfoW rc={rc}"
    try:
        sddl = wintypes.LPWSTR()
        ok = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd, 1, OWNER_SI | DACL_SI, ctypes.byref(sddl), None)
        assert ok, "SD->SDDL conversion failed"
        try:
            return sddl.value
        finally:
            k32.LocalFree(sddl)
    finally:
        k32.LocalFree(psd)


_SDDL_RE = re.compile(
    r"^O:(?P<owner>S-1-\S+?)D:(?P<flags>\w*)"
    r"\(A;;(?P<rights>[^;]+);;;(?P<trustee>S-1-\S+)\)$")


def _rights_are_file_all(rights: str) -> bool:
    """0x1F01FF == FILE_GENERIC_ALL; the SD->SDDL converter renders an
    exact match as the friendly token "FA", anything else as hex."""
    if rights.upper() == "FA":
        return True
    try:
        return int(rights, 16) == 0x1F01FF
    except ValueError:
        return False


def is_protected_owner_only(sddl: str, sid: str) -> bool:
    """Exactly one ACE: FILE_ALL_ACCESS for the token user, on a
    PROTECTED (inheritance-cut) DACL. P is always the first control flag
    when SE_DACL_PROTECTED is set; the informational AI bit may follow."""
    m = _SDDL_RE.match(sddl)
    if not m:
        return False
    return (m.group("flags").startswith("P")
            and m.group("owner") == sid
            and _rights_are_file_all(m.group("rights"))
            and m.group("trustee") == sid)


# ------------------------------------------------------------------ unit tests

def test_dacl_error_contract():
    check("DaclError subclasses OSError (all `except OSError` sites stay live)",
          issubclass(wtssh.DaclError, OSError))


def test_sid_resolution():
    if not NT:
        return skip("token user SID resolution")
    sid1 = wtssh._token_user_sid_string()
    sid2 = wtssh._token_user_sid_string()
    check("token user SID is S-1-... and cached",
          sid1.startswith("S-1-") and sid1.count("-") >= 4 and sid1 == sid2,
          sid1)


def test_real_apply():
    if not NT:
        return skip("real DACL apply + SDDL readback")
    sid = wtssh._token_user_sid_string()
    f = TMP / "keyfile"
    f.touch()
    wtssh.apply_owner_only_dacl(f)
    sddl = read_sddl(f)
    check("file: protected owner-only full-control DACL",
          is_protected_owner_only(sddl, sid), sddl)
    d = TMP / "rundir"
    d.mkdir()
    wtssh.apply_owner_only_dacl(d)
    sddl = read_sddl(d)
    check("dir: protected owner-only full-control DACL",
          is_protected_owner_only(sddl, sid), sddl)


def test_fail_closed_and_optout():
    if not NT:
        return skip("fail-closed / opt-out behavior")
    real = wtssh._ctypes_protected_dacl
    saved_env = os.environ.pop("WTSSH_ALLOW_LOOSE_ACL", None)
    f = TMP / "loose"
    f.touch()

    def boom(path):
        raise wtssh.DaclError(5, "SetNamedSecurityInfoW", str(path))

    wtssh._ctypes_protected_dacl = boom
    wtssh._LOOSE_ACL_WARNED = False
    try:
        try:
            wtssh.apply_owner_only_dacl(f)
            check("fail-closed: DaclError raised without opt-out",
                  False, "no exception")
        except wtssh.DaclError:
            check("fail-closed: DaclError raised without opt-out", True)

        os.environ["WTSSH_ALLOW_LOOSE_ACL"] = "1"
        err = io.StringIO()
        with redirect_stderr(err):
            wtssh.apply_owner_only_dacl(f)
        first = err.getvalue()
        check("opt-out: degrades with the one-time warning",
              "owner-only DACL NOT applied" in first
              and "WTSSH_ALLOW_LOOSE_ACL=1" in first, first)
        err = io.StringIO()
        with redirect_stderr(err):
            wtssh.apply_owner_only_dacl(f)
        check("opt-out: warning fires exactly once per process",
              err.getvalue() == "", err.getvalue())
    finally:
        wtssh._ctypes_protected_dacl = real
        wtssh._LOOSE_ACL_WARNED = False
        if saved_env is None:
            os.environ.pop("WTSSH_ALLOW_LOOSE_ACL", None)
        else:
            os.environ["WTSSH_ALLOW_LOOSE_ACL"] = saved_env


def boom(path):
    raise wtssh.DaclError(5, "SetNamedSecurityInfoW", str(path))


def test_secure_write_propagates():
    if not NT:
        return skip("secure_write DaclError propagation")
    real = wtssh._ctypes_protected_dacl
    wtssh._ctypes_protected_dacl = boom
    saved_loose = os.environ.pop("WTSSH_ALLOW_LOOSE_ACL", None)
    p = TMP / "map.json"
    p.touch()
    try:
        try:
            wtssh.secure_write(p, b"{}")
            check("secure_write surfaces DaclError (caller decides)",
                  False, "no exception")
        except wtssh.DaclError:
            check("secure_write surfaces DaclError (caller decides)", True)
    finally:
        wtssh._ctypes_protected_dacl = real
        if saved_loose is not None:
            os.environ["WTSSH_ALLOW_LOOSE_ACL"] = saved_loose


def test_no_stranded_partial_dirs():
    if not NT:
        return skip("partial-dir self-cleanup")
    import tempfile as _tf
    real = wtssh._ctypes_protected_dacl
    wtssh._ctypes_protected_dacl = boom
    saved_run = os.environ.get("WTSSH_RUN_DIR")
    saved_loose = os.environ.pop("WTSSH_ALLOW_LOOSE_ACL", None)
    saved_tmpdir = _tf.tempdir
    run_root = TMP / "run"
    os.environ["WTSSH_RUN_DIR"] = str(run_root)
    # isolate the mkdtemp root: the before/after glob must not race with
    # concurrent wtssh processes creating wtssh-key-* in the real %TEMP%
    _tf.tempdir = str(TMP)
    try:
        try:
            wtssh.make_run_dir()
            check("make_run_dir raises DaclError", False, "no exception")
        except wtssh.DaclError:
            pass
        leftovers = list(run_root.iterdir()) if run_root.exists() else []
        check("make_run_dir removes its partial dir",
              leftovers == [], leftovers)

        tmp = Path(_tf.gettempdir())  # == the sandbox TMP now
        before = set(tmp.glob("wtssh-key-*"))
        try:
            wtssh.secure_mkkey(b"not-secret")
            check("secure_mkkey raises DaclError", False, "no exception")
        except wtssh.DaclError:
            pass
        stranded = set(tmp.glob("wtssh-key-*")) - before
        check("secure_mkkey removes its partial keydir",
              not stranded, stranded)
    finally:
        wtssh._ctypes_protected_dacl = real
        _tf.tempdir = saved_tmpdir
        if saved_run is None:
            os.environ.pop("WTSSH_RUN_DIR", None)
        else:
            os.environ["WTSSH_RUN_DIR"] = saved_run
        if saved_loose is not None:
            os.environ["WTSSH_ALLOW_LOOSE_ACL"] = saved_loose


class _CaptureErr(io.StringIO):
    """StringIO that tolerates main()'s sys.stderr.reconfigure()."""

    def reconfigure(self, *args, **kwargs):
        pass


def test_main_converts_dacl_error():
    """main() must turn an escaping DaclError into the clean fail-closed
    die(4) (remediation message), never a bare traceback."""
    def boom_action(args):
        raise wtssh.DaclError(5, "SetNamedSecurityInfoW", r"X:\fat\run")

    real = wtssh.action_doctor
    wtssh.action_doctor = boom_action
    err = _CaptureErr()
    code = None
    try:
        with redirect_stderr(err):
            try:
                wtssh.main(["doctor"])
            except SystemExit as e:
                code = e.code
    finally:
        wtssh.action_doctor = real
    check("main() converts DaclError to clean die(4) with remediation",
          code == 4 and "cannot apply the owner-only DACL" in err.getvalue()
          and "WTSSH_ALLOW_LOOSE_ACL=1" in err.getvalue(),
          f"code={code} stderr={err.getvalue()[:160]!r}")


def test_atomic_write_owner_only_real():
    if not NT:
        return skip("atomic_write_owner_only real apply")
    f = TMP / "atomic-target.json"
    wtssh.atomic_write_owner_only(f, b"{}")
    sid = wtssh._token_user_sid_string()
    sddl = read_sddl(f)
    check("atomic_write_owner_only lands a protected file (post-replace)",
          is_protected_owner_only(sddl, sid), sddl)


def main():
    test_dacl_error_contract()
    test_sid_resolution()
    test_real_apply()
    test_fail_closed_and_optout()
    test_secure_write_propagates()
    test_no_stranded_partial_dirs()
    test_atomic_write_owner_only_real()
    test_main_converts_dacl_error()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} -> {FAILURES}")
        return 1
    print("all DACL tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
