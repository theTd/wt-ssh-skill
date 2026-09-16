"""Offline tests for the --tunnel SOCKS gate (socks_gate_* in wtssh.py):
no ssh, no vault, no FileZilla -- the gate is exercised against loopback
fakes that play the FileZilla client and the private anonymous `ssh -D`
upstream.

  1. greeting: an anonymous-only client is refused (0xFF); non-SOCKS
     garbage is dropped without a reply and without hurting the gate.
  2. RFC 1929: wrong user / wrong password -> 0x01 and close; the right
     pair -> 0x00 (constant-time compares live in the gate).
  3. CONNECT relay: the target bytes reach the fake upstream byte-exact
     (IPv4 and domain ATYP), data flows both ways, half-close propagates.
  4. only CONNECT: BIND -> REP 0x07; unknown ATYP -> REP 0x08.
  5. upstream failure mapping: nothing on the private port -> REP 0x05.
  6. private-port ownership (Windows): a private port held by a foreign
     "tunnel" pid refuses with REP 0x01; our own pid relays (real
     GetExtendedTcpTable, the test's listener row vs a wrong pid).

Run:  python tests/test_socks_gate.py
"""
import os
import socket
import sys
import threading
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

FAILURES: list[str] = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeUpstream:
    """An anonymous-SOCKS5 `ssh -D` stand-in: negotiates no-auth, records
    each connection's CONNECT bytes verbatim, replies success, then echoes
    application bytes until EOF."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(8)
        self.requests: list[bytes] = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _addr = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(conn,),
                             daemon=True).start()

    @staticmethod
    def _read(conn: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("EOF mid-frame")
            buf.extend(chunk)
        return bytes(buf)

    def _conn(self, conn: socket.socket):
        try:
            self._read(conn, 3)                 # VER NMETHODS METHODS
            conn.sendall(bytes((5, wtssh.SOCKS_METHOD_NOAUTH)))
            head = self._read(conn, 4)          # VER CMD RSV ATYP
            atyp = head[3]
            if atyp == 0x03:
                ln = self._read(conn, 1)[0]
                addr = bytes((ln,)) + self._read(conn, ln)
            else:
                addr = self._read(conn, {1: 4, 4: 16}.get(atyp, 0))
            port_b = self._read(conn, 2)
            self.requests.append(head + addr + port_b)
            conn.sendall(bytes((5, 0, 0, 1, 0, 0, 0, 0, 0, 0)))
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        self.srv.close()


class GateClient:
    """A minimal SOCKS5 client with RFC 1929 auth, shaped for asserting
    the gate's exact replies."""

    def __init__(self, port: int):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5.0)

    def _read(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("gate closed mid-frame")
            buf.extend(chunk)
        return bytes(buf)

    def greet(self, methods=(0x02,)) -> bytes:
        self.s.sendall(bytes((5, len(methods))) + bytes(methods))
        return self._read(2)

    def auth(self, user: str, password: str) -> bytes:
        u, p = user.encode(), password.encode()
        self.s.sendall(bytes((1, len(u))) + u + bytes((len(p),)) + p)
        return self._read(2)

    def request(self, host: bytes, port: int, atyp: int = 0x01,
                cmd: int = 0x01) -> None:
        if atyp == 0x03:
            addr = bytes((len(host),)) + host
        else:
            addr = host
        self.s.sendall(bytes((5, cmd, 0, atyp)) + addr
                       + port.to_bytes(2, "big"))

    def reply(self) -> bytes:
        """The gate's reply: REP from the fixed head, BND drained per ATYP."""
        head = self._read(4)
        atyp = head[3]
        if atyp == 0x01:
            self._read(6)
        elif atyp == 0x03:
            self._read(self._read(1)[0] + 2)
        elif atyp == 0x04:
            self._read(18)
        return head

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def open_gate(up: FakeUpstream, user: str, password: str,
              tunnel_pid) -> socket.socket:
    return wtssh.socks_gate_serve(free_port(), up.port, user, password,
                                  tunnel_pid)


def authed_client(gate: socket.socket, user: str = "u",
                  password: str = "p") -> GateClient:
    c = GateClient(gate.getsockname()[1])
    assert c.greet() == bytes((5, 2)), "method negotiation broke"
    assert c.auth(user, password) == bytes((1, 0)), "auth broke"
    return c


def test_greeting_and_auth():
    print("[gate greeting + RFC 1929]")
    up = FakeUpstream()
    gate = open_gate(up, "u-1", "p-1", os.getpid())
    try:
        c = GateClient(gate.getsockname()[1])
        r = c.greet((0x00,))
        check("anonymous-only greeting refused (2-byte 0xFF)",
              r == bytes((5, wtssh.SOCKS_METHOD_NONE)), repr(r))
        # the method reply is exactly two bytes; the gate then half-closes,
        # so the next read is a clean EOF -- no stray CONNECT-reply tail
        check("method refusal ends with a clean close",
              c.s.recv(4) == b"", "")
        c.close()

        g = GateClient(gate.getsockname()[1])
        g.s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        g.s.settimeout(5.0)
        try:
            eof = g.s.recv(16) == b""
        except OSError:
            eof = True
        check("non-SOCKS garbage dropped (EOF, gate alive)", eof, "")
        g.close()
        probe = GateClient(gate.getsockname()[1])
        check("gate still serving after garbage",
              probe.greet() == bytes((5, 2)), "")
        probe.close()

        c = GateClient(gate.getsockname()[1])
        check("greeting negotiates user/pass", c.greet() == bytes((5, 2)),
              "")
        check("wrong password refused", c.auth("u-1", "nope") == bytes((1, 1)),
              "")
        c.close()
        c = GateClient(gate.getsockname()[1])
        check("wrong user refused",
              c.greet() == bytes((5, 2))
              and c.auth("who", "p-1") == bytes((1, 1)), "")
        c.close()
        c = GateClient(gate.getsockname()[1])
        check("right pair accepted",
              c.greet() == bytes((5, 2))
              and c.auth("u-1", "p-1") == bytes((1, 0)), "")
        c.close()
    finally:
        gate.close()
        up.close()


def test_connect_relay():
    print("[CONNECT relay: byte-exact target, echo, half-close]")
    up = FakeUpstream()
    gate = open_gate(up, "u", "p", os.getpid())
    try:
        c = authed_client(gate)
        c.request(b"host.example", 2222, atyp=0x03)
        head = c.reply()
        check("CONNECT relayed: success reply",
              head == bytes((5, 0, 0, 1)), repr(head))
        want = bytes((5, 1, 0, 3, len(b"host.example"))) + b"host.example" \
            + (2222).to_bytes(2, "big")
        check("upstream saw the exact target bytes",
              up.requests == [want], repr(up.requests))
        c.s.sendall(b"ping")
        echo = b""
        while len(echo) < 4:
            echo += c.s.recv(4 - len(echo))
        check("application bytes flow both ways", echo == b"ping", repr(echo))
        c.s.shutdown(socket.SHUT_WR)
        check("half-close propagates back as EOF", c.s.recv(16) == b"", "")
        c.close()

        c = authed_client(gate)
        c.request(socket.inet_aton("10.1.2.3"), 80)
        head = c.reply()
        check("IPv4 ATYP relayed: success reply",
              head == bytes((5, 0, 0, 1))
              and up.requests[-1] == bytes((5, 1, 0, 1))
              + socket.inet_aton("10.1.2.3") + (80).to_bytes(2, "big"),
              repr((head, up.requests[-1])))
        c.close()

        c = authed_client(gate)
        c.request(socket.inet_pton(socket.AF_INET6, "::1"), 443, atyp=0x04)
        head = c.reply()
        check("IPv6 ATYP relayed: success reply",
              head == bytes((5, 0, 0, 1))
              and up.requests[-1] == bytes((5, 1, 0, 4))
              + socket.inet_pton(socket.AF_INET6, "::1")
              + (443).to_bytes(2, "big"),
              repr((head, up.requests[-1])))
        c.close()
    finally:
        gate.close()
        up.close()


def test_request_validation():
    print("[only CONNECT; known ATYPs]")
    up = FakeUpstream()
    gate = open_gate(up, "u", "p", os.getpid())
    try:
        c = authed_client(gate)
        c.request(socket.inet_aton("127.0.0.1"), 1, cmd=0x02)
        head = c.reply()
        check("BIND refused with REP 0x07",
              head[1] == wtssh.SOCKS_REP_CMD_NOTSUP, repr(head))
        # the gate closes without draining the rest of the refused frame,
        # so Windows may answer the next read with RST instead of EOF --
        # either ends the connection, which is all this asserts
        try:
            closed = c.s.recv(4) == b""
        except OSError:
            closed = True
        check("refused connection is closed", closed, "")
        c.close()

        c = authed_client(gate)
        c.request(b"", 1, atyp=0x05)
        head = c.reply()
        check("unknown ATYP refused with REP 0x08",
              head[1] == wtssh.SOCKS_REP_ATYP_NOTSUP, repr(head))
        c.close()
    finally:
        gate.close()
        up.close()


def test_upstream_refused():
    print("[upstream failure mapping]")
    dead = free_port()          # nothing will ever listen there
    gate = wtssh.socks_gate_serve(free_port(), dead, "u", "p", None)
    try:
        c = authed_client(gate)
        c.request(socket.inet_aton("127.0.0.1"), 443)
        head = c.reply()
        check("dead private port -> REP 0x05",
              head[1] == wtssh.SOCKS_REP_REFUSED, repr(head))
        c.close()
    finally:
        gate.close()


def test_private_port_ownership():
    print("[private-port ownership guard]")
    if sys.platform != "win32":
        print("  skip (GetExtendedTcpTable is Windows-only)")
        return
    # foreign "tunnel" pid: the private port IS held (by this test process,
    # via the fake upstream), but the gate is told the tunnel is another
    # pid -> refuse with REP 0x01 instead of relaying to a hijacked port
    up = FakeUpstream()
    gate = open_gate(up, "u", "p", os.getpid() + 1)
    try:
        c = authed_client(gate)
        c.request(socket.inet_aton("127.0.0.1"), 443)
        head = c.reply()
        check("foreign tunnel pid refused (REP 0x01)",
              head[1] == wtssh.SOCKS_REP_GENERAL, repr(head))
        check("nothing reached the upstream",
              up.requests == [], repr(up.requests))
        c.close()
    finally:
        gate.close()
        up.close()
    # our own pid: the identical topology relays
    up = FakeUpstream()
    gate = open_gate(up, "u", "p", os.getpid())
    try:
        c = authed_client(gate)
        c.request(socket.inet_aton("127.0.0.1"), 443)
        head = c.reply()
        check("own-pid listener relays",
              head == bytes((5, 0, 0, 1)) and len(up.requests) == 1,
              repr((head, up.requests)))
        c.close()
    finally:
        gate.close()
        up.close()


def main():
    test_greeting_and_auth()
    test_connect_relay()
    test_request_validation()
    test_upstream_refused()
    test_private_port_ownership()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} -> {FAILURES}")
        return 1
    print("all socks-gate tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
