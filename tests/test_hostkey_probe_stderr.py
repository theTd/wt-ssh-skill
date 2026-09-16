"""Unit tests for auth-none host-key probe stderr filtering.

The probe reaches the auth stage with PreferredAuthentications=none and
OpenSSH prints e.g. `user@10.0.0.1: Permission denied (publickey,...)`.
That line must be dropped; fingerprints, yes/no prompts, warnings, and
transport errors must stay.

Run:  python tests/test_hostkey_probe_stderr.py
"""
import io
import os
import sys
import tempfile
import types
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-hk-"))
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
    (TMP / "run").mkdir(parents=True, exist_ok=True)
    (TMP / "shim").mkdir(parents=True, exist_ok=True)
    (TMP / "log").mkdir(parents=True, exist_ok=True)


def test_noise_classifier():
    noise = [
        "user@10.0.0.1: Permission denied (publickey,keyboard-interactive).\n",
        "root@gateway: Permission denied (publickey).\n",
        "Permission denied (publickey).\n",
        "user@10.0.0.1: Permission denied (publickey,keyboard-interactive).\r\n",
        "alice@host: Authentications that can continue: publickey\n",
        "Authentications that can continue: publickey,keyboard-interactive\n",
        "user@2001:db8::1: Permission denied (publickey).\n",
        "user@[2001:db8::1]: Permission denied (publickey,keyboard-interactive).\n",
        "@2001:db8::1: Permission denied (publickey).\n",
        "@[2001:db8::1]: Authentications that can continue: publickey\n",
    ]
    keep = [
        "The authenticity of host '10.0.0.1 (10.0.0.1)' can't be established.\n",
        "ED25519 key fingerprint is SHA256:abcdef.\n",
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
        "Warning: Permanently added '10.0.0.1' (ED25519) to the list of known hosts.\n",
        "ssh: connect to host 10.0.0.1 port 22: Connection timed out\n",
        "user@10.0.0.1: Connection refused\n",
        "Host key verification failed.\n",
        "wtssh: host key for example-host ([10.0.0.1]:22) is not known yet\n",
        "ssh: /home/u/.ssh/known_hosts: Permission denied\n",
        "user@2001:db8::1: Connection refused\n",
    ]
    for line in noise:
        check(f"drop noise {line!r}",
              wtssh._is_hostkey_probe_auth_noise(line), line)
    for line in keep:
        check(f"keep valuable {line!r}",
              not wtssh._is_hostkey_probe_auth_noise(line), line)


def test_prefix_flush_rules():
    # Host-key yes/no prompt has no trailing newline -- must NOT be held.
    prompt = "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
    check("yes/no prompt is not a noise prefix",
          not wtssh._could_be_hostkey_probe_auth_noise_prefix(prompt),
          prompt)

    check("authenticity banner is not a noise prefix",
          not wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "The authenticity of host '10.0.0.1 (10.0.0.1)' "
              "can't be established."),
          "authenticity")

    check("developing user@host is held",
          wtssh._could_be_hostkey_probe_auth_noise_prefix("user@10.0.0.1"))
    check("developing user@host: is held",
          wtssh._could_be_hostkey_probe_auth_noise_prefix("user@10.0.0.1: "))
    check("developing Permission denied is held",
          wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "user@10.0.0.1: Permission den"))
    check("user@host: Connection is NOT held as noise",
          not wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "user@10.0.0.1: Connection"))
    check("bare user@IPv6 (no message yet) is held",
          wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "user@2001:db8::1"))
    check("IPv6 developing Permission denied is held",
          wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "user@2001:db8::1: Permission den"))
    check("bracket-IPv6 developing Permission denied is held",
          wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "user@[2001:db8::1]: Permission den"))
    check("IPv6 Connection is NOT held as noise",
          not wtssh._could_be_hostkey_probe_auth_noise_prefix(
              "user@2001:db8::1: Connection"))


def test_forwarder_filters_stream():
    src = io.StringIO(
        "The authenticity of host '10.0.0.1 (10.0.0.1)' can't be established.\n"
        "ED25519 key fingerprint is SHA256:abc.\n"
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
        "Warning: Permanently added '10.0.0.1' (ED25519) "
        "to the list of known hosts.\n"
        "user@10.0.0.1: Permission denied (publickey,keyboard-interactive).\n"
        "ssh: connect to host 10.0.0.1 port 22: Connection timed out\n"
    )
    dest = io.StringIO()
    wtssh._forward_hostkey_probe_stderr(src, dest)
    out = dest.getvalue()
    check("keeps authenticity line",
          "can't be established" in out, out)
    check("keeps fingerprint",
          "ED25519 key fingerprint" in out, out)
    check("keeps yes/no prompt live",
          "Are you sure you want to continue connecting" in out, out)
    check("keeps permanently-added warning",
          "Permanently added" in out, out)
    check("drops Permission denied",
          "Permission denied" not in out, out)
    check("keeps connection timed out",
          "Connection timed out" in out, out)


def test_forwarder_chunked_noise_line():
    """Permission denied arriving as split writes must still be dropped."""
    class ChunkReader:
        def __init__(self, chunks):
            self._chunks = list(chunks)

        def read(self, _n):
            return self._chunks.pop(0) if self._chunks else ""

    src = ChunkReader([
        "user@10.0.0.1: ",
        "Permission denied (publickey).\n",
        "Host key verification failed.\n",
    ])
    dest = io.StringIO()
    wtssh._forward_hostkey_probe_stderr(src, dest)
    out = dest.getvalue()
    check("chunked Permission denied dropped",
          "Permission denied" not in out and "user@10.0.0.1" not in out, out)
    check("chunked valuable line kept",
          "Host key verification failed." in out, out)

    # 256-byte boundary can cut inside the local username before '@'.
    # Fingerprint truncated to SHA256:ab so len(prefix) stays exactly 256
    # after the generic `user` placeholder (was a 3-char local username).
    prefix = (
        "The authenticity of host '10.0.0.1 (10.0.0.1)' can't be established.\n"
        "ED25519 key fingerprint is SHA256:ab.\n"
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
        "Warning: Permanently added '10.0.0.1' (ED25519) "
        "to the list of known hosts.\n"
        "user"
    )
    check("fixture lands mid-username at 256", len(prefix) == 256,
          f"len={len(prefix)}")
    src = ChunkReader([
        prefix,
        "@10.0.0.1: Permission denied (publickey,keyboard-interactive).\n"
        "ssh: connect to host 10.0.0.1 port 22: Connection timed out\n",
    ])
    dest = io.StringIO()
    wtssh._forward_hostkey_probe_stderr(src, dest)
    out = dest.getvalue()
    check("256-split keeps fingerprint",
          "ED25519 key fingerprint" in out, out)
    check("256-split keeps yes/no prompt",
          "Are you sure you want to continue connecting" in out, out)
    check("256-split drops Permission denied",
          "Permission denied" not in out, out)
    # Leak shape if the held mid-username prefix were flushed early:
    # it would sit right after the known_hosts warning (`hosts.\nuser…`)
    # or as `user@…` if the whole noise line escaped. Avoid bare
    # `"user" not in out` — too collision-prone with ordinary English.
    check("256-split does not leak bare username",
          "hosts.\nuser" not in out and "user@" not in out, out)
    check("256-split keeps timed out",
          "Connection timed out" in out, out)

    check("orphan @host Permission denied is noise",
          wtssh._is_hostkey_probe_auth_noise(
              "@10.0.0.1: Permission denied (publickey).\n"))
    check("bare username token is held as prefix",
          wtssh._could_be_hostkey_probe_auth_noise_prefix("user"))

    src = ChunkReader([
        "user@",
        "2001:db8::1: Permission denied (publickey).\n",
        "Host key verification failed.\n",
    ])
    dest = io.StringIO()
    wtssh._forward_hostkey_probe_stderr(src, dest)
    out = dest.getvalue()
    check("IPv6 chunked Permission denied dropped",
          "Permission denied" not in out and "2001:db8" not in out, out)
    check("IPv6 chunked valuable line kept",
          "Host key verification failed." in out, out)

    # Cut after the IPv6 host, before the `: message` separator -- the case
    # that broke when the separator was `:\s*` (IPv6 `::` looked final).
    src = ChunkReader([
        "user@2001:db8::1",
        ": Permission denied (publickey).\n",
        "Host key verification failed.\n",
    ])
    dest = io.StringIO()
    wtssh._forward_hostkey_probe_stderr(src, dest)
    out = dest.getvalue()
    check("IPv6 host-tail split drops Permission denied",
          "Permission denied" not in out and "2001:db8" not in out
          and "user@" not in out, out)
    check("IPv6 host-tail split keeps valuable line",
          "Host key verification failed." in out, out)

    src = ChunkReader([
        "user@[2001:db8::1]: ",
        "Permission denied (publickey).\n",
        "ssh: /tmp/known_hosts: Permission denied\n",
    ])
    dest = io.StringIO()
    wtssh._forward_hostkey_probe_stderr(src, dest)
    out = dest.getvalue()
    check("bracket-IPv6 auth noise dropped",
          "user@[2001:db8::1]" not in out, out)
    check("known_hosts file Permission denied kept",
          "ssh: /tmp/known_hosts: Permission denied" in out, out)


def test_run_probe_uses_filter(monkeypatch_attr=None):
    """_run_hostkey_probe_ssh pipes stderr through the filter."""
    written = []

    class FakeStderr:
        def write(self, s):
            written.append(s)

        def flush(self):
            pass

        def close(self):
            pass

        def read(self, _n):
            # unused; Popen.stderr is the pipe we read
            return ""

    class FakeProc:
        def __init__(self):
            self.stderr = io.StringIO(
                "ED25519 key fingerprint is SHA256:xyz.\n"
                "user@10.0.0.1: Permission denied (publickey).\n"
            )
            self._code = 255

        def wait(self):
            return self._code

    saved_popen = wtssh.subprocess.Popen
    saved_err = sys.stderr

    def fake_popen(*_a, **_k):
        return FakeProc()

    wtssh.subprocess.Popen = fake_popen
    sys.stderr = FakeStderr()
    try:
        code = wtssh._run_hostkey_probe_ssh(
            ["ssh", "-o", "PreferredAuthentications=none", "10.0.0.1"],
            env=dict(os.environ))
    finally:
        wtssh.subprocess.Popen = saved_popen
        sys.stderr = saved_err

    text = "".join(written)
    check("probe exit code preserved", code == 255, code)
    check("probe keeps fingerprint on stderr",
          "ED25519 key fingerprint" in text, text)
    check("probe drops Permission denied on stderr",
          "Permission denied" not in text, text)


def main():
    setup_env()
    print("hostkey probe stderr filter")
    test_noise_classifier()
    test_prefix_flush_rules()
    test_forwarder_filters_stream()
    test_forwarder_chunked_noise_line()
    test_run_probe_uses_filter()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        sys.exit(1)
    print("all passed")


if __name__ == "__main__":
    main()
