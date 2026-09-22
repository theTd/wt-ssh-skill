#!/usr/bin/env python3
"""Manage an ssh host book inside Windows Terminal settings.json.

Subcommands:
  list [--full]                     list ssh entries (grouped; --group -> flat rows)
  show NAME                         dump one profile object
  add NAME --host H [--user U] [--port P] [--key PATH|wtv:KEYNAME] [--title T]
      [--jump J] [--extra "SSH OPTS"] [--default] [--hidden] [--sftp]
  edit NAME [--user U] [--host H] [--port P] [--key PATH|wtv:KEYNAME|none]
      [--title T] [--jump J|none] [--extra "SSH OPTS"|none]
      [--hidden|--visible] [--sftp|--no-sftp]
  import [--ssh-config PATH]        import hosts from an OpenSSH client config
  rename OLD NEW                    rename entry (guid preserved)
  remove NAME [--force]             delete profile + folder membership
                                    (refused while other entries --jump it,
                                    unless --force)
  move NAME [--top|--bottom|--before X|--after Y]
  get-default / set-default NAME
  guid NAME                         print resolved GUID
  secret set/remove/list            vault-sealed passphrases (no get: no plaintext export)
  key import KEYNAME KEYFILE        seal a STANDALONE key (+passphrase) into the TPM
                                    vault as KEYNAME.wtv -- no host entry needed
  key list                          list standalone keys + referencing entries
  key rename OLD NEW                rename a standalone key, re-pointing its users
  key export KEYNAME OUTFILE        export it back as a passphrase-protected file
  key remove KEYNAME [--force]      delete a standalone key (refused while an
                                    entry references it; --force drops them)
  vault init/remove/status          TPM CNG key vault (confidentiality layer)
  connect NAME [-- ssh ARGS]        unwrap vault -> ssh
  filezilla NAME [--keyfile PATH]   sync the entry into FileZilla's Site
                                    Manager (a folder named after the group)
                                    and connect it via `filezilla -c` (alias: fz)

NAME is the entry name without the `ssh:` prefix (e.g. `alpha`).
--jump accepts an existing entry name (expanded to user@host[:port]) or a
verbatim user@host[:port] spec; `none` (edit only) clears it.
--hidden keeps an entry out of the WT ssh folder menu (the host book the
user sees) while leaving the ssh: profile in place so other entries can
--jump it. Jump hosts are added this way unless the user asked to open
the jumper itself from the menu (--visible / omit --hidden).
--extra carries verbatim ssh options (-L/-D/-o/...) that wtssh does not model;
they are preserved in place across edits.
--group (before the subcommand, or $WTSSH_GROUP, default "ssh") picks the
newTabMenu folder for ssh: entries; --sftp-group (or $WTSSH_SFTP_GROUP,
default "sftp") picks the folder for sftp: companions. Entry names are
unique across all groups.

Only touches ssh: profiles and folder entries. Backs up to
settings.json.wtssh.bak before every write. JSON round-trip validated before
replacing the file. The vault layer is optional: without it, plain
`-i` entries work as ordinary ssh.
"""
from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

GROUP = os.environ.get("WTSSH_GROUP") or "ssh"  # newTabMenu folder ssh: rows own
SFTP_GROUP = os.environ.get("WTSSH_SFTP_GROUP") or "sftp"  # sftp: companions
PREFIX = "ssh:"        # profile name prefix marking membership
# Companion profiles (`sftp:<name>`): FileZilla menu entries managed ALONGSIDE
# an ssh entry. They are not book entries -- no ssh read path may ever parse
# them (`"sftp:...".startswith("ssh:")` is false on purpose), and their
# commandline is the canonical `sftp_line()` shape only. Default pin is the
# `sftp` newTabMenu folder (independent of --group); --sftp-group overrides.
SFTP_PREFIX = "sftp:"
SFTP_ICON = "\U0001F5C2"  # 🗂 tab/dividers: the file-transfer sibling of 🔗
PWSH_GUID = "{574e775e-4f2a-5b96-ac1e-a2962a402336}"  # published PowerShell 7
# Sealed blobs are v2 envelopes {"v":2,"alg":"AES-256-GCM","name",...} whose
# AAD is the blob TYPE: a key blob can never be read as a passphrase blob (or
# vice versa). The OWNER name (key name, or entry name for a passphrase) lives
# inside the encrypted payload and is re-checked on read, so relocating a blob
# still fails closed.
KEY_AAD = "wtssh:key"
SECRET_AAD = "wtssh:secret"
# Windows file names cannot contain these, and ':' is worse than an error:
# `KEYS_DIR / 'a:b.wtv'` collapses to a drive-relative path ('a:b.wtv'), so the
# blob would land OUTSIDE the keys directory. Guarded by name_is_usable (read
# paths, lenient) and checked_key_name (KEYNAME arguments, dies early).
FILE_UNSAFE_CHARS = frozenset(':*?"<>|')
# cmd.exe metacharacters. A routed commandline starts with a .cmd shim, which
# CreateProcessW silently launches via `cmd /c` -- there `&` splits commands,
# `<`/`>` redirect, `^` escapes, and `%VAR%` expands EVEN INSIDE double
# quotes. Entry names (`connect <name>`) and key names (`-i wtv:<name>`) are
# embedded verbatim in routed lines, so no name a routed line can carry may
# contain them. Verified by injection PoC: a name `foo&whoami>x`
# runs `whoami` when the tab opens, via `cmd /c`.
CMD_UNSAFE_CHARS = frozenset('&|<>^%!')
# Payload format inside a sealed blob. 4 = "name" is the standalone key's own
# name (or the entry name for a passphrase secret). There is no older format;
# an unknown fmt is simply an error.
PAYLOAD_FMT = 4
# Askpass map schema. v2 carries two typed slots: "keys" (truncated container
# path -> one-shot {"pw","uses"} | null tombstone) and "login" (the stored
# secret's password with its registered identities). The map is written and
# consumed within a single connect, so the dispatcher REFUSES any other
# shape -- no legacy spelling exists and none is tolerated.
MAP_SCHEMA_VERSION = 2
# Entry commandlines reference a standalone vault key as -i wtv:<name> (the
# value is shlex-quoted when the name contains spaces). This is the ONLY
# spelling: a literal path into KEYS_DIR is not a key reference.
KEY_REF_PREFIX = "wtv:"
# Rendered jump chains: opaque ssh_config block names (C3 -- user-controlled
# strings never become Host patterns), and the %.100s truncation OpenSSH
# applies to the askpass prompt's key path (readpass.c), which the
# dispatcher's map keys must mirror.
BLOCK_TARGET = "wtssh-target"
ASKPASS_PROMPT_MAX = 100
RUN_DIR_PREFIX = "wtssh-run-"
# ssh options that consume the following token as their value; every other
# '-'-prefixed token is a boolean flag. Both kinds survive in `extra`.
VALUE_OPTS = frozenset((
    "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l",
    "-m", "-O", "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w",
))
SCRIPTS = Path(__file__).resolve().parent
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA")
                    or (Path.home() / "AppData/Local"))
SECRETS_DIR = Path(os.environ.get(
    "WTSSH_SECRETS", LOCALAPPDATA / "wtssh/secrets",
))
# Private keys imported into the managed vault. Each .wtv file is an
# AES-256-GCM blob holding the key bytes and (optional) passphrase; the
# wrapping DEK is released only by the TPM vault key (CNG consent dialog).
KEYS_DIR = Path(os.environ.get(
    "WTSSH_KEYS", LOCALAPPDATA / "wtssh/keys",
))
# ssh-agent cache index: per-key .pub selectors plus keys.json
# {key: {fp, ttl, loaded_at, expires_at}}. Public material only (no
# passphrases, no private bytes) -- the secrets live in the agent's
# memory for the TTL. Overridable for drills like SECRETS_DIR/KEYS_DIR.
AGENT_DIR = Path(os.environ.get(
    "WTSSH_AGENT_DIR", LOCALAPPDATA / "wtssh/agent",
))


# Message of the most recent die(): for callers that catch the SystemExit
# (import turns per-entry failures into skips) and still want the reason.
# die() exits the process everywhere else, so a stale value cannot leak.
_LAST_DIE: str | None = None


def die(msg: str, code: int = 1):
    global _LAST_DIE
    _LAST_DIE = msg
    print(f"wtssh: error: {msg}", file=sys.stderr)
    sys.exit(code)


# ------------------------------------------------------------------- exec

# A bare name on a CreateProcess command line resolves against the CURRENT
# DIRECTORY first (CreateProcessW search order: application dir, CWD,
# System32, ..., PATH), and since Python 3.12 shutil.which() prepends the CWD
# to its search too unless NoDefaultCurrentDirectoryInExePath is set. Running
# wtssh from an untrusted directory that carries a planted ssh.exe/
# powershell.exe would therefore route the vault DEK, passphrases and
# host-key probes through attacker code -- a zero-click variant of the
# same-user threat. Every external binary wtssh spawns goes through
# find_bin/resolve_bin: explicit absolute names are honored verbatim, bare
# names resolve through the user's PATH with the CWD excluded, then the
# System32 anchor -- a miss never degrades back to a bare name.
_BIN_ANCHORS = {
    "ssh": ("SystemRoot", "System32/OpenSSH/ssh.exe"),
    "ssh-add": ("SystemRoot", "System32/OpenSSH/ssh-add.exe"),
    "ssh-keygen": ("SystemRoot", "System32/OpenSSH/ssh-keygen.exe"),
    "powershell": ("SystemRoot",
                   "System32/WindowsPowerShell/v1.0/powershell.exe"),
    "clip": ("SystemRoot", "System32/clip.exe"),
}


def _bin_in_cwd(found: str) -> bool:
    """Would the absolute path `found` land inside the current directory?"""
    try:
        return os.path.normcase(os.path.abspath(found)).startswith(
            os.path.normcase(os.getcwd() + os.sep))
    except OSError:
        return False


def find_bin(name: str) -> str | None:
    """Absolute path of what `name` would execute, or None.

    An absolute (or ~-expanded) name is honored verbatim; an explicit
    relative form (./x, dir/x, drive-relative) is refused instead of
    guessed; a bare name resolves through PATH with the CWD excluded --
    NoDefaultCurrentDirectoryInExePath (set in main) makes shutil.which()
    agree, and the isabs/CWD checks below enforce it even where that env
    var is not set (tests, direct imports) -- then the System32 anchor."""
    if name.startswith("~"):
        p = Path(name).expanduser()
        return str(p) if (p.is_absolute() and p.is_file()) else None
    p = Path(name)
    if p.is_absolute():
        return str(p) if p.is_file() else None
    if os.path.basename(name) != name:
        return None  # explicit relative form: refusing beats resolving it
    found = shutil.which(name)
    if found and os.path.isabs(found) and not _bin_in_cwd(found):
        return found
    anchor = _BIN_ANCHORS.get(name.lower().removesuffix(".exe"))
    if anchor and os.environ.get(anchor[0]):
        cand = Path(os.environ[anchor[0]]) / anchor[1]
        if cand.is_file():
            return str(cand)
    return None


def resolve_bin(name: str) -> str:
    """find_bin or die: the secret-carrying spawns (vault, ssh, dialogs)
    must fail loudly, not run whatever a hostile CWD offers."""
    hit = find_bin(name)
    if hit is None:
        die(f"cannot locate '{name}': searched PATH (current directory "
            f"excluded) and the System32 anchors; refusing a CWD-relative "
            f"match -- check your PATH for '.' or relative entries")
    return hit


# ------------------------------------------------------------------ paths

# Windows Terminal settings.json, in probe order: the Store (stable) package,
# the Store preview package, then a per-user unpackaged install.
WT_SETTINGS_CANDIDATES = (
    "Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/localState/settings.json",
    "Packages/Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe/localState/settings.json",
    "Microsoft/Windows Terminal/settings.json",
)
# Resolved on first use: --settings (in main) beats $WTSSH_SETTINGS beats the
# probe, and nothing may touch the filesystem at import time.
SETTINGS: Path | None = None


def discover_settings() -> Path:
    env = os.environ.get("WTSSH_SETTINGS")
    if env:
        return Path(env)
    tried = [LOCALAPPDATA / rel for rel in WT_SETTINGS_CANDIDATES]
    for cand in tried:
        if cand.exists():
            return cand
    die("Windows Terminal settings.json not found; looked at:\n  "
        + "\n  ".join(str(p) for p in tried)
        + "\npass --settings PATH or set WTSSH_SETTINGS")


def settings_path() -> Path:
    global SETTINGS
    if SETTINGS is None:
        SETTINGS = discover_settings()
    return SETTINGS


def lock_path() -> Path:
    p = settings_path()
    return p.with_name(p.name + ".wtssh.lock")


def backup_path() -> Path:
    p = settings_path()
    return p.with_name(p.name + ".wtssh.bak")


def shim_path() -> Path:
    """Stable launcher for routed commandlines: a .cmd on disk survives the
    interpreter moving or being reinstalled (an interpreter path burned into
    every profile would turn routed tabs dead)."""
    return Path(os.environ.get("WTSSH_SHIM_DIR", LOCALAPPDATA / "wtssh")) / "wtssh.cmd"


def ensure_shim() -> Path:
    """(Re)write the launcher when its content drifted; returns its path."""
    shim = shim_path()
    body = ("@echo off\r\n"
            f'"{sys.executable}" "{SCRIPTS / "wtssh.py"}" %*\r\n').encode("utf-8")
    if not shim.exists() or shim.read_bytes() != body:
        shim.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(shim, body)
    return shim


# ------------------------------------------------------- load / save

def load() -> dict:
    path = settings_path()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot parse {path}: {e}")


def render(obj, indent: int) -> str:
    """Windows Terminal's own serialization style (verified byte-level against
    a WT-written settings.json): 4-space indent,
    alphabetically sorted keys, non-empty nested containers open on their own
    line (`"font": \\n{`), empty containers inline (`"defaults": {},`),
    non-ASCII escaped as \\uXXXX, LF endings, no trailing newline."""
    pad = "    " * indent
    inner = "    " * (indent + 1)
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        items = []
        for k, v in sorted(obj.items()):
            rendered = render(v, indent + 1)
            if len(rendered) > 2 and rendered[0] in "{[":
                items.append(f"{json.dumps(k)}: \n{inner}{rendered}")
            else:
                items.append(f"{json.dumps(k)}: {rendered}")
        body = (",\n" + inner).join(items)
        return "{\n" + inner + body + "\n" + pad + "}"
    if isinstance(obj, list):
        if not obj:
            return "[]"
        items = [render(v, indent + 1) for v in obj]
        body = (",\n" + inner).join(items)
        return "[\n" + inner + body + "\n" + pad + "]"
    return json.dumps(obj, ensure_ascii=True)


def save(data: dict):
    text = render(data, 0)
    try:
        json.loads(text)
    except json.JSONDecodeError as e:  # defensive: never ship invalid JSON
        die(f"internal error: generated invalid JSON: {e}", 2)
    path = settings_path()
    try:
        if path.exists():
            atomic_write(backup_path(), path.read_bytes())
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".wtssh.", suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.unlink(tmp)
        except (OSError, NameError, UnboundLocalError):
            pass
        die(f"write failed: {e}")


def atomic_write(path: Path, payload: bytes):
    """Write bytes via temp file + os.replace (atomic on Windows/POSIX)."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".wtssh.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def sweep_stale_tmps():
    """Remove .wtssh.*.tmp orphans (hard-crash leftovers) next to settings
    and in the secrets/keys dirs (sealed ciphertext only, but tidy)."""
    now = time.time()
    for folder in (settings_path().parent, SECRETS_DIR, KEYS_DIR):
        try:
            stale = [p for p in folder.glob(".wtssh.*.tmp")
                     if now - p.stat().st_mtime > 300]  # 5min: in-flight safe
        except OSError:
            continue  # dir missing: nothing to sweep
        for p in stale:
            try:
                p.unlink()
            except OSError:
                pass
    sweep_orphan_keydirs()


class Lock:
    """Advisory O_EXCL lock; stale after 60s. Waits up to 60s for a live
    holder, then treats it as stale, breaks it, and proceeds. `path`
    defaults to the settings.json lock; other written files (FileZilla's
    sitemanager.xml) pass their own."""

    def __init__(self, path: Path | None = None):
        self._path = path

    def __enter__(self):
        lk = self._path or lock_path()
        deadline = time.time() + 60
        while True:
            try:
                fd = os.open(lk, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w") as f:
                    f.write(str(os.getpid()))
                sweep_stale_tmps()
                return self
            except FileExistsError:
                try:
                    stale = time.time() - lk.stat().st_mtime > 60
                except FileNotFoundError:
                    continue  # holder released between open and stat
                if stale:
                    try:
                        lk.unlink()
                    except OSError:
                        pass
                    continue
                if time.time() >= deadline:
                    die("another wtssh process holds the lock (60s)", 3)
                time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            (self._path or lock_path()).unlink()
        except OSError:
            pass

# ------------------------------------------------------- settings accessors

def folder_by_name(data: dict, name: str) -> dict | None:
    for e in data.get("newTabMenu", []):
        if e.get("type") == "folder" and e.get("name") == name:
            return e
    return None


def get_folder_by_name(data: dict, name: str, create: bool = False) -> dict | None:
    folder = folder_by_name(data, name)
    if folder is None and create:
        folder = {"type": "folder", "name": name, "icon": None,
                  "inline": "never", "allowEmpty": False, "entries": []}
        # append: a new group must not jump above the user's existing menus
        data.setdefault("newTabMenu", []).append(folder)
    return folder


def ssh_folder(data: dict) -> dict | None:
    return folder_by_name(data, GROUP)


def get_folder(data: dict, create: bool = False) -> dict | None:
    return get_folder_by_name(data, GROUP, create=create)


def sftp_menu_folder(data: dict) -> dict | None:
    return folder_by_name(data, SFTP_GROUP)


def get_sftp_folder(data: dict, create: bool = False) -> dict | None:
    return get_folder_by_name(data, SFTP_GROUP, create=create)


def guid_folder_names(data: dict, guid: str) -> list[str]:
    """Every newTabMenu folder name that pins this guid, in menu order."""
    names: list[str] = []
    for e in data.get("newTabMenu", []):
        if e.get("type") != "folder" or not isinstance(e.get("entries"), list):
            continue
        if any(x.get("profile") == guid for x in e["entries"]):
            names.append(str(e.get("name")))
    return names


def guid_folder_name(data: dict, guid: str) -> str | None:
    """Name of the first newTabMenu folder that pins this guid, or None."""
    names = guid_folder_names(data, guid)
    return names[0] if names else None


def profile_hidden(p: dict) -> bool:
    """WT `hidden: true` plus (by invariant) not listed in any newTabMenu
    folder: the entry stays in the book for --jump / connect / print, but
    does not appear in the dropdown host book. Missing key = visible."""
    return bool(p.get("hidden"))


def sweep_guid_from_folders(data: dict, guid: str) -> None:
    for e in data.get("newTabMenu", []):
        if e.get("type") == "folder" and isinstance(e.get("entries"), list):
            e["entries"] = [x for x in e["entries"]
                            if x.get("profile") != guid]


def pin_guid_in_group(data: dict, guid: str) -> None:
    folder = get_folder(data, create=True)
    entries = folder.setdefault("entries", [])
    if not any(x.get("profile") == guid for x in entries):
        entries.append({"type": "profile", "icon": None, "profile": guid})


def hide_entry(data: dict, p: dict) -> None:
    """Take the entry off every WT folder menu. Refuses if it is the
    default profile -- a hidden default would still open on new tab."""
    name = p["name"][len(PREFIX):]
    if data.get("defaultProfile") == p.get("guid"):
        die(f"entry '{name}' is the default profile; "
            f"'wtssh set-default' something else before hiding it")
    p["hidden"] = True
    sweep_guid_from_folders(data, p["guid"])


def show_entry(data: dict, p: dict) -> None:
    """Put the entry in THIS group's menu only. Sweep first: a profile
    already pinned in another folder (or still pinned while hidden) would
    otherwise appear in two WT folders at once."""
    p["hidden"] = False
    sweep_guid_from_folders(data, p["guid"])
    pin_guid_in_group(data, p["guid"])


# ------------------------------------------------- sftp: companion profiles

def sftp_line(name: str) -> str:
    """commandline of the `sftp:<name>` companion profile. Like routed lines
    it launches through the .cmd shim (cmd /c), so the name must be
    cmd-safe -- the fixed payload (`filezilla <name> --tunnel auto`) carries
    no metacharacters itself. The entry's identity (host, port, key, jump
    chain) is resolved from the book at click time by `wtssh filezilla
    <name>`, so later `edit` calls need no propagation; `--tunnel auto`
    means "SOCKS tunnel only when the entry has a jump" (jump-free vault
    entries still export an ephemeral session key on the direct path)."""
    if not cmd_name_is_safe(name):
        die(f"entry name '{name}' contains cmd metacharacters; an SFTP menu "
            f"entry would run them via cmd.exe when it opens -- rename the "
            f"entry first: wtssh rename '{name}' <safe-name>")
    return (f"{shquote(str(shim_path()))} filezilla {shquote(name)} "
            f"--tunnel auto")


def sftp_profile_ok(p: dict, name: str) -> bool:
    """True when p is the canonical `sftp:<name>` companion: exactly the
    five tokens sftp_line emits (shim matched by basename, path ignored)."""
    try:
        toks = ssh_tokens(p.get("commandline") or "")
    except ValueError:
        return False
    return (len(toks) == 5
            and os.path.basename(shunquote(toks[0])).lower() == "wtssh.cmd"
            and toks[1] == "filezilla"
            and shunquote(toks[2]) == name
            and toks[3] == "--tunnel" and toks[4] == "auto")


def find_sftp_profile(data: dict, name: str) -> dict | None:
    full = SFTP_PREFIX + name
    for p in data["profiles"]["list"]:
        if p.get("name") == full:
            return p
    return None


def create_sftp_profile(data: dict, name: str) -> tuple[dict, bool]:
    """Create (or normalize an existing) `sftp:<name>` companion and pin it
    in the SFTP group folder (default name `sftp`, independent of --group).
    Right-after-ssh adjacency only happens when that ssh entry is itself
    pinned in the SFTP folder (SFTP_GROUP == GROUP and the ssh row is
    visible there). Returns (profile, changed); only writes in-memory
    `data` -- the caller owns Lock + save."""
    line = sftp_line(name)          # dies on a cmd-unsafe legacy name
    ensure_shim()
    existing = find_sftp_profile(data, name)
    if existing is not None:
        p = existing
        line_changed = p.get("commandline") != line
        p["commandline"] = line     # normalize; idempotent re-runs repair
        icon_changed = p.get("icon") != SFTP_ICON
        if icon_changed:
            p["icon"] = SFTP_ICON
        close_changed = p.get("closeOnExit") != "never"
        if close_changed:
            # direct filezilla launches must keep the WT tab open; automatic
            # closes the job and KILL_ON_JOB_CLOSE reaps FileZilla with it
            p["closeOnExit"] = "never"
        pins = guid_folder_names(data, p["guid"])
        uniquely_in_sftp = pins == [SFTP_GROUP]
        fields_changed = line_changed or icon_changed or close_changed
        if uniquely_in_sftp:
            # already the only pin, and in the target folder: repair
            # fields in place, do not reshuffle menu order
            return p, fields_changed
        changed = True              # wrong folder / dual-pin / unpinned
    else:
        guid = "{" + str(uuid.uuid4()) + "}"
        while by_guid(data, guid):  # same paranoia as action_add
            guid = "{" + str(uuid.uuid4()) + "}"
        p = {"closeOnExit": "never", "commandline": line,
             "guid": guid, "icon": SFTP_ICON, "name": SFTP_PREFIX + name}
        data["profiles"]["list"].append(p)
        changed = True
    ssh = find_profile(data, name)
    folder = get_sftp_folder(data, create=True)
    sweep_guid_from_folders(data, p["guid"])
    entries = folder.setdefault("entries", [])
    idx = None
    if ssh is not None:
        idx = next((i for i, e in enumerate(entries)
                    if e.get("profile") == ssh["guid"]), None)
    entries.insert(idx + 1 if idx is not None else len(entries),
                   {"type": "profile", "icon": None, "profile": p["guid"]})
    return p, changed


def delete_sftp_profile(data: dict, name: str) -> bool:
    """Remove the `sftp:<name>` companion (profile + every folder pin).
    False when there is none. Only writes in-memory `data`."""
    p = find_sftp_profile(data, name)
    if p is None:
        return False
    data["profiles"]["list"].remove(p)
    sweep_guid_from_folders(data, p.get("guid", ""))
    return True


def find_profile(data: dict, name: str) -> dict | None:
    full = PREFIX + name
    for p in data["profiles"]["list"]:
        if p.get("name") == full:
            return p
    return None


def require_profile(data: dict, name: str) -> dict:
    p = find_profile(data, name)
    if p is None:
        die(f"no ssh entry named '{name}' (looked for profile '{PREFIX}{name}')")
    return p


def by_guid(data: dict, guid: str) -> dict | None:
    for p in data["profiles"]["list"]:
        if p.get("guid") == guid:
            return p
    return None


def clean_name(name: str) -> str:
    n = name.strip()
    if not n:
        die("entry name must not be empty")
    if any(c in n for c in '/\\"') or n.startswith("-"):
        # '/'/'\\' would collide in secret filenames ('a/b' == 'a_b' after
        # sanitizing); '"' breaks commandline round-trips; leading '-' makes
        # the name look like a flag to argparse/ssh.
        die(f"entry name must not contain '/', '\\\\' or '\"', or start with '-': {name!r}")
    return n


def name_is_usable(name: str) -> bool:
    """clean_name's rules as a predicate (bulk import skips bad aliases
    instead of aborting the whole run). Still not a file-name check (key
    NAMES go through `key_name_is_safe` too), but it refuses cmd
    metacharacters: import aliases and `wtv:` refs become tokens of routed
    commandlines, where the cmd.exe layer would execute them (see
    CMD_UNSAFE_CHARS)."""
    return bool(name) and not any(c in name for c in '/\\"') \
        and not name.strip().startswith("-") \
        and cmd_name_is_safe(name)


def key_name_is_safe(name: str) -> bool:
    """A KEYNAME becomes `<name>.wtv` inside KEYS_DIR, so the Windows-invalid
    set is not cosmetic: `KEYS_DIR / 'a:b.wtv'` collapses to a drive-relative
    path ('a:b.wtv') and the blob would be written OUTSIDE the keys
    directory. It also becomes a `-i wtv:<name>` token inside routed
    commandlines, so cmd metacharacters are refused as well."""
    return not any(c in FILE_UNSAFE_CHARS or ord(c) < 32
                   or c in CMD_UNSAFE_CHARS for c in name)


def checked_key_name(name: str) -> str:
    """clean_name + file-name safety, for KEYNAME arguments: fail before any
    path is composed. Entry names deliberately do NOT go through this -- a
    pre-existing entry may legitimately carry such characters, and dying here
    would poison read-only commands."""
    n = clean_name(name)
    bad = sorted({c for c in n if c in FILE_UNSAFE_CHARS
                  or c in CMD_UNSAFE_CHARS or ord(c) < 32})
    if bad:
        die(f"key name must not contain "
            f"{', '.join(repr(c) for c in bad)} (it becomes the file name "
            f"'{n}.wtv'): {name!r}")
    return n


def cmd_name_is_safe(name: str) -> bool:
    """True when a name can ride inside a routed commandline without the
    cmd.exe layer acting on it. Quoting neutralizes `& | < > ^` for argument
    splitting, but `%VAR%` expands even inside double quotes, and control
    characters are separators -- all refused, never quoted around."""
    return not any(c in CMD_UNSAFE_CHARS or ord(c) < 32 for c in name)


# What a routed line's EMBEDDED ssh command (everything after `--`) must not
# carry. `& | < > ^` split/redirect/escape in cmd even from inside quoted
# values (cmd does not honor backslash-escaped quotes, so an embedded `\"`
# closes the quoting early); `%VAR%` expands inside double quotes, and `!var!`
# does too whenever delayed expansion is on -- off by default under `cmd /c`,
# but a user registry override (Command Processor\DelayedExpansion or an
# AutoRun that turns it on) flips it globally, so `!` is refused as well
# instead of betting on the default. Control characters are separators in
# both contexts. (NAMES are refused harder: CMD_UNSAFE_CHARS.)
PAYLOAD_UNSAFE_CHARS = frozenset('&|<>^%!')


def cmd_risky_payload_chars(line: str) -> str:
    """Sorted unique cmd-metacharacters an embedded ssh payload carries
    ('' when clean). One definition of "cannot ride a routed line", shared by
    routed_line (die), import (skip with reason), secret set / key import
    (refuse before any blob is written) -- so the four cannot drift."""
    return "".join(sorted({c for c in line
                           if c in PAYLOAD_UNSAFE_CHARS or ord(c) < 32}))


def checked_entry_name(name: str) -> str:
    """clean_name + cmd metacharacter rejection, for NEW entry names (`add`,
    `rename <new>`). Legacy entries whose name predates this rule stay
    manageable: `rename` accepts them as `<old>` -- that is the documented
    escape -- and `list` warns about routed ones."""
    n = clean_name(name)
    bad = sorted({c for c in n if c in CMD_UNSAFE_CHARS or ord(c) < 32})
    if bad:
        die(f"entry name must not contain cmd metacharacters "
            f"{', '.join(repr(c) for c in bad)}: {name!r} (routed tabs are "
            f"launched via cmd.exe, where they split or expand the "
            f"commandline)")
    return n


def resolve_fallback_default(data: dict) -> str:
    """Pick a defaultProfile that actually exists on this machine, for when
    the current default entry is being deleted: exact 'PowerShell', then any
    'PowerShell*', then 'Command Prompt', then the published PowerShell 7
    GUID. A GUID that no profile carries would leave WT with a ghost default."""
    profiles = [p for p in data.get("profiles", {}).get("list", [])
                if p.get("guid")]

    def named(p: dict) -> str:
        return str(p.get("name") or "")

    for p in profiles:
        if named(p) == "PowerShell":
            return p["guid"]
    for p in profiles:
        if named(p).startswith("PowerShell"):
            return p["guid"]
    for p in profiles:
        if named(p) == "Command Prompt":
            return p["guid"]
    for p in profiles:
        if p["guid"] == PWSH_GUID:
            return PWSH_GUID
    die("no PowerShell/Command Prompt profile to fall back to after removing "
        "the default entry; run 'wtssh set-default <name>' to pick one")


# ------------------------------------------------------- commandline parse

def ssh_tokens(commandline: str) -> list[str]:
    """Quote-aware split of an ssh commandline; falls back to naive split
    when quotes are unbalanced (hand-edited files). Windows filenames cannot
    contain double quotes, and shlex(posix=False) does not honor our \"
    escaping -- so any backslash-escaped quote (only producible by shquote on
    a value with an embedded quote) is rejected before it can corrupt
    parsing. Plain wrapping quotes are unaffected.

    RAISES ValueError on such a line, so do NOT call this directly from a new
    site: reach it through a wrapper that decides the failure mode --
    `cmd_fields` (read paths that
    report `fix or remove it first`), `toks_lenient`/`plain_line_lenient`
    (inspect paths that must never die), or `strict_tokens_or_die` (write paths
    and connect, which die with the entry name)."""
    if '\\"' in commandline or "\\'" in commandline:
        raise ValueError("escaped quotes in commandline")
    try:
        return shlex.split(commandline, posix=False)
    except ValueError:
        return commandline.split()


# The only launcher a routed line can carry is the installed shim; no second
# spelling is accepted.
ROUTED_LAUNCHERS = frozenset(("wtssh.cmd",))


def is_routed(toks: list[str]) -> bool:
    """True for "<shim> connect NAME -- ssh ..." routed lines.
    shlex(posix=False) keeps wrapping quotes, so the first token is unquoted
    before basename (a shim under a path with spaces is always quoted)."""
    return (len(toks) >= 4 and "connect" in toks and "--" in toks
            and os.path.basename(shunquote(toks[0])).lower().removesuffix(".exe")
            in ROUTED_LAUNCHERS)


def cmd_fields(p: dict) -> dict:
    """Split a commandline into modeled fields plus what must be re-emitted
    verbatim: `extra` (option tokens that precede the destination) and `tail`
    (everything after it -- a remote command, hand-written extras).

    The destination is the FIRST bare token. Tokens after it stay in `tail`
    instead of being folded into `extra`, because build_commandline emits
    `extra` *before* the destination: folding a remote command in would move
    it in front of the host (or worse, promote it to the host) on the next
    edit. Repeated -i/-p/-J: the first occurrence models the field, later
    ones ride in `extra` in place, which reproduces the written token order
    (ssh accumulates -i; for -p/-J the last still wins)."""
    out = {"user": None, "host": None, "port": None, "key": None, "jump": None,
           "extra": [], "tail": [], "routed": None}
    try:
        toks = ssh_tokens(p.get("commandline") or "")
    except ValueError as e:
        die(f"{e} in entry '{p.get('name', '?')}'; fix or remove it first")
    if is_routed(toks):
        # fields live after the "--" separator; "connect NAME" precedes it.
        # A hand-edited line can end right after `connect`, so bound the index
        # instead of trusting it (same family as the `-i` blind index).
        cpos = toks.index("connect")
        out["routed"] = shunquote(toks[cpos + 1]) if cpos + 1 < len(toks) else None
        toks = toks[toks.index("--") + 1:]
    positional = []
    seen = set()
    i = 1
    while i < len(toks):
        t = toks[i]
        if positional:
            # ssh stops option parsing at the destination, so the remote
            # command keeps its own flags ('ssh host tail -f x' must not
            # hoist -f in front of the host)
            out["tail"] += toks[i:]
            break
        if t in ("-i", "-p", "-J") and i + 1 < len(toks):
            if t in seen:
                out["extra"] += [toks[i], toks[i + 1]]
            else:
                seen.add(t)
                val = shunquote(toks[i + 1])
                if t == "-i":
                    out["key"] = val
                elif t == "-p":
                    out["port"] = val
                else:
                    out["jump"] = val
            i += 2
        elif t in VALUE_OPTS and i + 1 < len(toks):
            # value-taking option we do not model (-L/-D/-o/...): keep the
            # pair verbatim and in order, so ssh still sees what was written
            out["extra"] += [toks[i], toks[i + 1]]
            i += 2
        elif t.startswith("-") and len(t) > 1:
            # boolean flag (-t, -A, -4) or an attached-value option
            # (-p22, -oKey=Value): a single token either way, kept verbatim
            out["extra"].append(t)
            i += 1
        else:
            positional.append(t)
            i += 1
    if positional:
        dest = shunquote(positional[0])
        if "@" in dest:
            out["user"], out["host"] = dest.rsplit("@", 1)
        else:
            out["host"] = dest
    fields = [out["key"], out["port"], out["jump"], out["user"], out["host"]]
    if any('"' in f for f in fields if f):
        # shquote escapes embedded quotes as \", but shlex(posix=False) does
        # not reproduce that escaping losslessly; a quote surviving unquote
        # means we cannot round-trip the value -- refuse instead of corrupt.
        die(f"embedded double quote in parsed fields of entry "
            f"'{p.get('name', '?')}'; fix or remove it first")
    return out


def shquote(value: str) -> str:
    """Quote a token iff it contains whitespace (ssh.exe parses its command
    line with CommandLineToArgvW semantics, which honor double quotes)."""
    if value and not any(c.isspace() for c in value) and '"' not in value:
        return value
    return '"' + value.replace('"', '\\"') + '"'


def shunquote(token: str) -> str:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1].replace('\\"', '"')
    return token


def field_unroundtrippable(value) -> bool:
    """True when shquote's output for this value would contain an escaped
    quote sequence that ssh_tokens refuses. Two shapes do it: a value
    carrying a double quote, and a value with whitespace ending in a
    backslash (shquote appends '\\\"' right at the trailing backslash:
    'C:\\dir with space\\' -> '"C:\\dir with space\\"')."""
    if value is None:
        return False
    v = str(value)
    return '"' in v or (any(c.isspace() for c in v) and v.endswith("\\"))


def check_cmdline_field(field: str, value) -> None:
    """Refuse any CLI field that would make the emitted commandline
    un-round-trippable. The stored line is re-parsed by ssh_tokens, which
    dies on an escaped quote, so a stored line that cannot be re-parsed would
    poison the entry for list/edit/connect -- and edit parses the same line,
    so it could not be fixed in place. Reject at the write path instead,
    with the offending field named."""
    if field_unroundtrippable(value):
        die(f"--{field} must not contain a double quote, or end in a "
            f"backslash after whitespace (the emitted ssh command line "
            f"could not be re-parsed): {value!r}")


def expand_key(key: str | None) -> str | None:
    """ssh.exe does not expand '~'; do it for the user/agent."""
    if not key:
        return key
    if key.startswith("~/") or key.startswith("~\\"):
        return os.path.expanduser(key)
    return key


def parse_extra(spec: str | None) -> tuple[list[str], list[str]] | None:
    """--extra "..." -> (option tokens, post-destination tokens), already
    quoted for emission. 'none' clears both; None (flag absent) means 'leave
    the caller's current values alone'.

    The split mirrors cmd_fields: everything up to the first bare token is an
    option (kept before the destination), from there on it is the tail (a
    remote command). So '--extra "-L 1:2:3 uptime"' cannot silently promote
    'uptime' to the destination."""
    if spec is None:
        return None
    if spec.strip() == "none":
        return [], []
    try:
        # ssh-config-style tokenizer: backslashes stay literal (a Windows
        # path like C:\Tools\p.exe survives verbatim), '"' quotes a run,
        # '\"' is a literal quote. shlex(posix=True) ate every backslash.
        toks = _split_value(spec, strict=True)
    except ValueError as e:
        die(f"cannot parse --extra {spec!r}: {e}")
    if any('"' in t for t in toks):
        die(f"--extra must not contain double quotes (ssh.exe command lines "
            f"cannot carry them): {spec!r}")
    opts: list[str] = []
    tail: list[str] = []
    i = 0
    while i < len(toks) and toks[i].startswith("-") and len(toks[i]) > 1:
        if toks[i] in VALUE_OPTS and i + 1 < len(toks):
            opts += [toks[i], toks[i + 1]]
            i += 2
        else:
            opts.append(toks[i])
            i += 1
    tail = [shquote(t) for t in toks[i:]]
    return [shquote(t) for t in opts], tail


def build_commandline(user, host, port, key, jump, extra=None,
                      tail=None) -> str:
    parts = ["ssh"]
    if key:
        parts += ["-i", shquote(expand_key(key))]
    if jump:
        parts += ["-J", shquote(jump)]
    if port:
        parts += ["-p", str(port)]
    parts += list(extra or [])  # verbatim; already quoted by parse/parse-time
    dest = f"{user}@{host}" if user else host
    parts.append(shquote(dest))
    parts += list(tail or [])   # remote command / hand-written trailing args
    line = " ".join(parts)
    # Final invariant, covering every field at once (incl. preserved tails
    # from legacy entries): what we store must round-trip through the same
    # tokenizer every read path uses. Per-field checks (check_cmdline_field)
    # give nicer errors earlier; this one is the backstop.
    try:
        ssh_tokens(line)
    except ValueError as e:
        die(f"built commandline cannot be re-parsed ({e}); refusing to "
            f"store it -- check the field values for embedded quotes or "
            f"trailing backslashes: {line!r}")
    return line


def resolve_jump(data: dict, spec: str, _seen: tuple = ()) -> str | None:
    """Entry name -> user@host[:port], chained through the entry's own jump
    (ssh -J comma chain). Literal specs pass through verbatim. Cycles die."""
    if not spec:
        return None
    if spec == "none":
        die("--jump none only clears a jump in `edit`; it is not a host")
    jp = find_profile(data, spec)
    if jp is None:
        return spec
    if spec in _seen:
        die(f"jump chain cycle through '{spec}'")
    f = cmd_fields(jp)
    if not f["host"]:
        die(f"jump entry '{spec}' has no parsable host in its commandline")
    hop = f"{f['user']}@{f['host']}" if f["user"] else f["host"]
    if f["port"]:
        hop += f":{f['port']}"
    if f["jump"]:
        upstream = resolve_jump(data, f["jump"], _seen + (spec,))
        if upstream:
            hop = f"{upstream},{hop}"
    return hop


def jump_specs_lenient(p: dict) -> list[str]:
    """-J hop specs without dying on a poisoned commandline (doctor)."""
    toks = toks_lenient(p.get("commandline") or "")
    if is_routed(toks):
        try:
            toks = toks[toks.index("--") + 1:]
        except ValueError:
            return []
    i = 1
    while i < len(toks):
        t = toks[i]
        if t == "-J" and i + 1 < len(toks):
            return _hop_specs(shunquote(toks[i + 1]))
        if t in VALUE_OPTS and i + 1 < len(toks):
            i += 2
            continue
        if t.startswith("-") and len(t) > 1:
            i += 1
            continue
        break
    return []


def jump_referrer_names(data: dict, name: str, *, strict: bool = True) -> list[str]:
    """Entry names whose stored -J hop spec includes `name` as a book-entry
    alias (preserve mode). Literal user@host hops are not referrers.
    strict (remove/rename): an unparsable sibling dies -- do not hide or
    delete a jumper while we cannot inventory who still --jump it.
    doctor passes strict=False and skips unreadable siblings."""
    refs: list[str] = []
    for p in data["profiles"]["list"]:
        n = str(p.get("name", ""))
        if not n.startswith(PREFIX):
            continue
        entry = n[len(PREFIX):]
        if entry == name:
            continue
        if strict:
            specs = _hop_specs(cmd_fields(p)["jump"])
        else:
            specs = jump_specs_lenient(p)
        if name in specs:
            refs.append(entry)
    return refs


def replace_hop_name(jump: str | None, old: str, new: str) -> str | None:
    if not jump:
        return jump
    specs = _hop_specs(jump)
    if old not in specs:
        return jump
    return ",".join(new if s == old else s for s in specs)


def store_ssh_line(p: dict, name: str, line: str) -> None:
    """Write an ssh commandline onto the profile, wrapping through the
    shim iff the entry is already routed or the new line needs the vault."""
    toks = toks_lenient(p.get("commandline") or "")
    routed = (is_routed(toks)
              or secret_path(name).exists()
              or bool(entry_key_refs(line)))
    if routed:
        ensure_shim()
        p["commandline"] = routed_line(name, {"commandline": line})
    else:
        p["commandline"] = line


def rewrite_jump_referrers(data: dict, old: str, new: str) -> list[str]:
    """Point every -J <old> hop at <new> after a rename. Skips the renamed
    profile itself (now named `new`)."""
    changed: list[str] = []
    for p in data["profiles"]["list"]:
        n = str(p.get("name", ""))
        if not n.startswith(PREFIX):
            continue
        entry = n[len(PREFIX):]
        if entry == new:
            continue
        f = cmd_fields(p)
        jump = replace_hop_name(f["jump"], old, new)
        if jump == f["jump"]:
            continue
        line = build_commandline(f["user"], f["host"], f["port"], f["key"],
                                 jump, f["extra"], f["tail"])
        store_ssh_line(p, entry, line)
        changed.append(entry)
    return changed


def new_profile(guid: str, name: str, user, host, port, key, jump, extra=None,
                tail=None, title=None, hidden: bool = False) -> dict:
    p = {
        "altGrAliasing": True,
        "antialiasingMode": "grayscale",
        "closeOnExit": "automatic",
        "colorScheme": "Campbell",
        "commandline": build_commandline(user, host, port, key, jump, extra,
                                         tail),
        "cursorShape": "bar",
        "font": {"face": "Cascadia Mono", "size": 12},
        "guid": guid,
        "hidden": bool(hidden),
        "historySize": 9001,
        "icon": "\U0001F517",
        "name": PREFIX + name,
        "padding": "8, 8, 8, 8",
        "snapOnInput": True,
        "startingDirectory": "%USERPROFILE%",
        "useAcrylic": False,
    }
    if title:
        p["tabTitle"] = title
    return p


def profile_row(p: dict, data: dict, full: bool) -> dict:
    f = cmd_fields(p)
    guid = p.get("guid", "")
    keys = profile_key_refs(p)
    row = {
        "name": p["name"][len(PREFIX):],
        "guid": guid,
        "user": f["user"], "host": f["host"], "port": f["port"],
        "key": f["key"], "jump": f["jump"], "extra": f["extra"] or None,
        "tail": f["tail"] or None,
        "jumpMode": p.get("jumpMode"),
        "title": p.get("tabTitle"),
        "hidden": profile_hidden(p),
        "passphrase": secret_path(p["name"][len(PREFIX):]).exists(),
        "vaultKey": bool(keys),
        "vaultKeys": [name for _path, name in keys],
        "vaultKeysMissing": [name for path, name in keys if not path.exists()],
        "default": data.get("defaultProfile") == guid,
    }
    comp = find_sftp_profile(data, p["name"][len(PREFIX):])
    if comp is not None:
        row["sftp"] = True
        sftp_in = guid_folder_name(data, comp.get("guid", ""))
        if sftp_in:
            row["sftpGroup"] = sftp_in
    if full:
        row["profile"] = p
    return row


# ------------------------------------------------------------------ actions

def folder_rows(data: dict, folder: dict | None, full: bool,
                warned: list) -> list[dict]:
    """Rows for the ssh: profiles a folder references (dangling guids are
    collected for a warning, not fatal)."""
    rows = []
    if not folder:
        return rows
    for e in folder.get("entries", []):
        if e.get("type") != "profile":
            continue
        p = by_guid(data, e.get("profile", ""))
        if p is None:
            warned.append(e.get("profile"))
            continue
        if not str(p.get("name", "")).startswith(PREFIX):
            # sftp: companions are not book rows -- they surface through
            # their ssh entry's `sftp` flag; parsing one as an ssh line
            # would emit a garbage row (name mangled by the ssh: strip)
            continue
        rows.append(profile_row(p, data, full))
    return rows


def ungrouped_rows(data: dict, full: bool, referenced: set) -> list[dict]:
    """ssh: profiles no folder references (WT shows them under 'remaining
    profiles'); surfaced so nothing is invisible. Hidden jump-host entries
    are excluded -- they are intentionally off-menu and listed under
    `hidden` instead."""
    rows = []
    for p in data["profiles"]["list"]:
        if not str(p.get("name", "")).startswith(PREFIX):
            continue
        if p.get("guid") in referenced or profile_hidden(p):
            continue
        row = profile_row(p, data, full)
        row["ungrouped"] = True
        rows.append(row)
    return rows


def hidden_rows(data: dict, full: bool) -> list[dict]:
    """ssh: profiles with hidden:true -- jump-host identity holders that
    stay in the book for --jump / flatten_chain but are kept out of the
    WT dropdown. Listed separately so the agent can still manage them."""
    return [profile_row(p, data, full)
            for p in data["profiles"]["list"]
            if str(p.get("name", "")).startswith(PREFIX) and profile_hidden(p)]


def warn_cmd_unsafe_routed(data: dict) -> None:
    """Routed entries whose NAME or embedded ssh command carries cmd
    metacharacters run them via cmd.exe when the tab opens (verified by
    injection PoC). add/rename/import refuse such names and payloads;
    pre-existing (or hand-edited) entries still surface here.
    Rename fixes a bad
    name; edit --host/--user/--extra fixes a bad payload; `remove` always
    works. Plain lines are not warned about: WT launches them without the
    cmd.exe layer."""
    bad_names: list[str] = []
    bad_payloads: list[tuple[str, str]] = []
    for p in data["profiles"]["list"]:
        if not str(p.get("name", "")).startswith(PREFIX):
            continue
        if not is_routed(toks_lenient(p.get("commandline") or "")):
            continue
        name = p["name"][len(PREFIX):]
        if not cmd_name_is_safe(name):
            bad_names.append(name)
        # scan the RAW line, not just the plain payload: a hand-edited entry
        # can carry a poisoned `connect <name>` argument while its profile
        # name is clean, and the whole line goes through cmd.exe
        bad = cmd_risky_payload_chars(p.get("commandline") or "")
        if bad:
            bad_payloads.append((name, bad))
    if bad_names:
        print("wtssh: warning: routed entries with cmd metacharacters in "
              "their name execute them via cmd.exe on tab open: "
              f"{bad_names} -- rename them: wtssh rename <name> <safe-name>",
              file=sys.stderr)
    for name, bad in bad_payloads:
        print(f"wtssh: warning: routed entry '{name}' carries cmd "
              f"metacharacters {' '.join(repr(c) for c in bad)} in its ssh "
              f"command -- they would run via cmd.exe when the tab opens; "
              f"remove them ('wtssh edit {name} --host/--user/--extra ...') "
              f"or remove the entry", file=sys.stderr)


def action_list(args):
    """Flat rows for one group (agent-friendly), or every group plus the
    ungrouped leftovers when no --group was given."""
    data = load()
    warn_cmd_unsafe_routed(data)
    warned: list = []
    if args.group is not None:
        payload = folder_rows(data, ssh_folder(data), args.full, warned)
        listed = {r["name"] for r in payload}
        # Only names that did NOT also land in the folder array -- a hidden
        # profile still pinned in the folder (broken invariant) is listed
        # above, and claiming it is "not listed" would lie.
        missing = [r["name"] for r in hidden_rows(data, False)
                   if r["name"] not in listed]
        if missing:
            names = ", ".join(missing)
            print(f"wtssh: note: {len(missing)} hidden jump-host "
                  f"entr{'y' if len(missing) == 1 else 'ies'} not listed "
                  f"({names}); omit --group to see the 'hidden' array",
                  file=sys.stderr)
    else:
        groups, referenced = {}, set()
        for e in data.get("newTabMenu", []):
            if e.get("type") != "folder" or not isinstance(e.get("entries"), list):
                continue
            rows = folder_rows(data, e, args.full, warned)
            referenced |= {r["guid"] for r in rows}
            if rows:  # folders holding no ssh entry are not ours to report
                key = str(e.get("name"))
                if key in groups:  # WT tolerates duplicate folder names
                    key = f"{key}#{len(groups) + 1}"
                    print(f"wtssh: warning: duplicate folder name in "
                          f"newTabMenu; reporting one as {key!r}",
                          file=sys.stderr)
                groups[key] = rows
        payload = {"groups": groups,
                   "ungrouped": ungrouped_rows(data, args.full, referenced),
                   "hidden": hidden_rows(data, args.full)}
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if warned:
        print(f"wtssh: warning: dangling group entries: {warned}", file=sys.stderr)


def action_show(args):
    data = load()
    print(json.dumps(require_profile(data, args.name), ensure_ascii=False, indent=2))


def action_guid(args):
    data = load()
    print(require_profile(data, args.name)["guid"])


def _parse_hopspec(spec: str) -> tuple[str | None, str, str | None]:
    """Split one -J hop spec '[user@]host[:port]' (ssh -J syntax; the caller
    splits the comma chain). IPv6 needs the bracket form to carry a port; an
    unbracketed token with a non-numeric tail stays one host, exactly like
    ssh treats it."""
    user = None
    rest = spec
    if "@" in rest:
        user, _, rest = rest.partition("@")
    port = None
    if rest.startswith("["):
        host, _, tail = rest.partition("]")
        host = host[1:]
        if tail.startswith(":"):
            port = tail[1:]
    elif rest.count(":") == 1:
        host, _, p = rest.partition(":")
        if p.isdigit():
            port = p
        else:
            host = rest
    else:
        host = rest
    return (user or None), host, (port or None)


def action_print(args):
    """Render an entry as an exact ssh invocation.
    --cmd prints the embedded ssh command line (what WT actually runs);
    --plan, the default, prints the hop/target structure as JSON WITHOUT any
    secret material -- vault keys appear as names, passphrases only as the
    boolean `secrets`. Pure reading: no vault, no writes, no config probes."""
    data = load()
    p = require_profile(data, args.name)
    name = p["name"][len(PREFIX):]
    if args.cmd:
        try:
            line = plain_line(p)
        except ValueError as e:
            print(f"wtssh: warning: commandline does not round-trip ({e}); "
                  f"showing the lenient form", file=sys.stderr)
            line = plain_line_lenient(p)
        print(line)
        return
    try:
        f = cmd_fields(p)
    except SystemExit:
        # A poisoned commandline (hand-edited settings.json): degrade to a
        # minimal plan instead of dying -- the same leniency --cmd already
        # has, and the same contract doctor keeps (exit 0, JSON out).
        print(json.dumps({
            "name": name,
            "error": _LAST_DIE or "commandline cannot be parsed",
            "commandline": p.get("commandline") or "",
        }, ensure_ascii=False, indent=2))
        return
    refs = profile_key_refs(p)
    hops = []
    for spec in [s.strip() for s in (f["jump"] or "").split(",") if s.strip()]:
        user, host, port = _parse_hopspec(spec)
        jp = find_profile(data, spec)
        hop: dict = {"spec": spec, "entry": None, "user": user, "host": host,
                     "port": port, "effective": spec, "keys": []}
        if jp is not None:
            try:
                hop["effective"] = resolve_jump(data, spec)
            except SystemExit:
                hop["effective"] = None
            hop["entry"] = spec
            hop["keys"] = [n for _path, n in profile_key_refs(jp)]
        hops.append(hop)
    print(json.dumps({
        "name": name,
        "jumpMode": p.get("jumpMode"),  # null == the preserve default
        "target": {"user": f["user"], "host": f["host"], "port": f["port"],
                   "keys": [n for _path, n in refs]},
        "hops": hops,
        "render": plan_public(*render_plan_safe(data, p)),
        "secrets": secret_path(name).exists(),
        "commandline": plain_line_lenient(p),
    }, ensure_ascii=False, indent=2))


def _user_config_entries() -> list[dict]:
    """Parsed ~/.ssh/config (best effort), for doctor's preserve/conflict
    checks. Missing or unreadable -> [] (doctor degrades to fewer checks,
    it must not turn into a config parser error report)."""
    path = Path.home() / ".ssh" / "config"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_ssh_config(text, path.parent)


def _doctor_findings(data: dict, p: dict,
                     cfg_entries: list[dict]) -> list[dict]:
    """Advisory self-checks for one entry. Levels:
    'warn' = likely real trouble, 'info' = future-renderer relevant fact."""
    name = p["name"][len(PREFIX):]
    out: list[dict] = []

    def add(level: str, check: str, msg: str) -> None:
        out.append({"level": level, "check": check, "msg": msg})

    # 1) the name as a config alias: preserve semantics and the coming
    #    renderer both depend on names that survive ssh_config matching
    if not name_is_usable(name):
        add("warn", "name-alias", "name cannot appear in a routed "
            "commandline (rename it)")
    bad_chars = sorted({c for c in name if c in "*?!"})
    if bad_chars:
        add("warn", "name-alias", f"name contains wildcard character(s) "
            f"{' '.join(bad_chars)}; a user-config Host pattern would match "
            f"it instead of a literal alias")
    if " " in name:
        add("info", "name-alias", "name contains a space; ssh_config "
            "aliases cannot contain spaces")

    # 2) vault key references resolve to real blobs
    refs = profile_key_refs(p)
    missing = [n for path, n in refs if not path.exists()]
    if missing:
        add("warn", "key-refs", f"references missing vault key(s): "
            f"{', '.join(repr(m) for m in missing)}")

    # 3) legacy coexistence the write paths now prevent (detect leftovers)
    if (refs or has_lexical_key_ref(p.get("commandline") or "")) \
            and secret_path(name).exists():
        add("warn", "ref-secret", "references a vault key AND has a stored "
            "passphrase; connect would ignore the passphrase")

    guid = p.get("guid")
    in_folder = False
    for e in data.get("newTabMenu", []):
        if e.get("type") != "folder" or not isinstance(e.get("entries"), list):
            continue
        if any(x.get("profile") == guid for x in e["entries"]):
            in_folder = True
            break

    # 3b) hidden jump host still pinned in a folder: WT still shows it
    if profile_hidden(p) and in_folder:
        add("warn", "hidden-menu",
            "hidden is set but this profile is still in a "
            "newTabMenu folder; Windows Terminal would still show "
            "it there -- run 'wtssh edit "
            f"{name} --hidden' to sweep the folder ref")

    # 3c) a hidden entry that is still the default profile (hand-edit /
    #     hide-then-someone-set-default race): new tabs would open it.
    if profile_hidden(p) and data.get("defaultProfile") == guid:
        add("warn", "hidden-default",
            "hidden entry is the default profile; new tabs would still "
            f"open it -- 'wtssh set-default' something else")

    # 3d) used as someone else's book-entry hop but still on a WT menu
    users = jump_referrer_names(data, name, strict=False)
    if users and (not profile_hidden(p) or in_folder):
        add("warn", "jump-menu",
            f"jump host for {users} but still appears in the WT menu; "
            f"'wtssh edit {name} --hidden' keeps the hop without listing "
            f"it (skip if the user asked to open this jumper from the "
            f"dropdown)")

    # 4) hop chain resolution: book entry vs user-config alias vs literal
    # first-obtained-wins: ssh uses the FIRST matching Host block, so
    # duplicate aliases must not let a later block shadow the advisory
    cfg_by_name: dict = {}
    for e in cfg_entries:
        cfg_by_name.setdefault(e["name"], e)
    f = cmd_fields(p)
    # 4b) stored-secret login dispatch needs a known identity: the
    # dispatcher answers only the prompt naming the registered user@host,
    # and without an explicit user the registered fallback is the OS
    # username -- an ssh-config User would silently never match
    if secret_path(name).exists() and not f["user"]:
        add("warn", "secret-user", "stored passphrase (password auth) "
            "without an explicit user: login dispatch registers the OS "
            "username, so an ssh-config User would not match -- set one "
            f"with 'wtssh edit {name} --user USER'")
    if f["jump"]:
        hop_specs = [s.strip() for s in f["jump"].split(",") if s.strip()]
        if name in hop_specs:
            add("warn", "hops", "entry jumps through itself")
        for spec in hop_specs:
            jp = find_profile(data, spec)
            if jp is not None:
                try:
                    eff = resolve_jump(data, spec)
                except SystemExit:
                    add("warn", "hops", f"hop chain through {spec!r} cannot "
                        f"be resolved (cycle or unparsable entry)")
                    continue
                add("info", "hops", f"hop {spec!r} resolves via the book "
                    f"entry -> {eff}")
            elif spec in cfg_by_name:
                ce = cfg_by_name[spec]
                if ce.get("jump"):
                    add("warn", "hops", f"user config alias {spec!r} "
                        f"carries its own ProxyJump {ce['jump']!r}; a "
                        f"rendered block would shadow it (config "
                        f"first-wins) -- the chain keeps the -J path while "
                        f"this hop is not a book entry")
                else:
                    add("info", "hops", f"hop {spec!r} comes from the user "
                        f"config alias")
            else:
                add("info", "hops", f"hop {spec!r} is neither a book entry "
                    f"nor a user-config alias; ssh connects to it as a "
                    f"literal host")

    # 5) dispatcher mechanics facts (the askpass dispatcher)
    sim = Path(tempfile.gettempdir()) / ("wtssh-key-" + "x" * 8) / "key"
    if len(str(sim)) > ASKPASS_PROMPT_MAX:
        add("info", "container-path", f"decrypted container path is "
            f"{len(str(sim))} chars; ssh truncates the askpass prompt at "
            f"{ASKPASS_PROMPT_MAX} chars, so the dispatcher matches "
            f"truncated paths")
    if " " in str(LOCALAPPDATA):
        add("info", "paths", "LOCALAPPDATA contains a space; rendered "
            "-F/ProxyCommand paths must always stay quoted (they do)")

    # 6) old ssh: passphrase dispatch would silently degrade to TTY prompts
    if refs or secret_path(name).exists():
        ok, ver = ssh_askpass_support()
        if not ok:
            add("warn", "ssh-version", f"{ver} predates SSH_ASKPASS_REQUIRE "
                f"(OpenSSH 8.4); passphrase dispatch degrades to terminal "
                f"prompts")
        elif ver.startswith(("version probe failed", "unrecognized")):
            # surface the fail-open note: the check ran, the version is
            # unknown, so the <8.4 guarantee is unverified for this entry
            add("info", "ssh-version", f"could not determine ssh version "
                f"({ver}); the askpass-requirement check was skipped")

    # 7) rendered chain: how the jump chain will actually connect
    plan, reason = render_plan_safe(data, p)
    rp = plan_public(plan, reason)
    if rp["mode"] != "legacy":
        if rp["pinPrompts"]:
            add("info", "render", f"chain renders to -F blocks at connect; "
                f"{rp['keys']} vault key(s) share 1 PIN prompt (batch unwrap)")
        else:
            add("info", "render", "chain renders to -F blocks at connect; "
                "no vault keys: no PIN prompt")
    elif reason:
        add("info", "render", f"chain keeps the -J path: {reason}")
    # the one refusal connect dies on, reported here with the SAME predicate
    # as build_render_plan: only an actively-dispatching connect refuses --
    # a no-credential/-no-askpass connect keeps the fully-interactive -J path
    hops_chain, _fl = flatten_chain(data, f["jump"]) if f["jump"] else ([], None)
    for hop in hops_chain:
        hn = hop["profile"]["name"][len(PREFIX):]
        if secret_path(hn).exists():
            if refs:
                add("warn", "render", f"hop {hop['spec']!r} holds a stored "
                    f"passphrase (password auth); a connect that dispatches "
                    f"vault keys refuses (the dispatcher cannot serve it) -- "
                    f"import the credential as a vault key or use "
                    f"--no-askpass")
            else:
                add("info", "render", f"hop {hop['spec']!r} holds a stored "
                    f"passphrase (password auth); the -J path stays fully "
                    f"interactive for it")
            break
    # plain-file identities in a dispatching chain: encrypted ones cannot be
    # answered by the dispatcher (best effort: key_encrypted may not know
    # the format; None findings are silent)
    if plan is not None and plan["keys"]:
        for b in plan["blocks"]:
            for ident in b["identities"]:
                if ident["kind"] != "file":
                    continue
                try:
                    enc = key_encrypted(Path(ident["path"]))
                except SystemExit:
                    enc = None
                if enc:
                    add("warn", "render", f"key file {ident['path']} (entry "
                        f"{b['entry']}) is passphrase-protected but not in "
                        f"the vault; the dispatcher cannot answer it")
    return out


def sftp_companion_findings(data: dict, only: str | None = None) -> dict:
    """Advisory findings for `sftp:` companion profiles, keyed by the
    companion's own name (`sftp:<entry>`). Only arises from hand-edited
    settings.json: every tool path (add/edit/remove/rename) keeps
    companions canonical, orphan-free and non-default."""
    out: dict = {}
    for p in data["profiles"]["list"]:
        n = str(p.get("name", ""))
        if not n.startswith(SFTP_PREFIX):
            continue
        ssh_name = n[len(SFTP_PREFIX):]
        if only is not None and ssh_name != only:
            continue
        findings: list = []
        if find_profile(data, ssh_name) is None:
            findings.append({
                "level": "warn", "check": "sftp-orphan",
                "msg": f"the ssh entry '{ssh_name}' no longer exists; this "
                       f"FileZilla menu entry is stale -- re-create the ssh "
                       f"entry, or remove it with "
                       f"'wtssh edit {ssh_name} --no-sftp'"})
        if not cmd_name_is_safe(ssh_name):
            findings.append({
                "level": "warn", "check": "sftp-cmd-unsafe",
                "msg": f"entry name '{ssh_name}' carries cmd metacharacters; "
                       f"this SFTP menu entry would run them via cmd.exe "
                       f"when it opens -- rename the entry first: "
                       f"wtssh rename '{ssh_name}' <safe-name>"})
        if not sftp_profile_ok(p, ssh_name):
            findings.append({
                "level": "warn", "check": "sftp-bad-line",
                "msg": f"commandline is not the canonical "
                       f"'<shim> filezilla {ssh_name} --tunnel auto' shape; "
                       f"re-create it: wtssh edit {ssh_name} --no-sftp, "
                       f"then wtssh edit {ssh_name} --sftp"})
        if data.get("defaultProfile") == p.get("guid"):
            findings.append({
                "level": "warn", "check": "sftp-default",
                "msg": "this SFTP entry is Windows Terminal's default "
                       "profile; every new tab would open FileZilla -- "
                       "'wtssh set-default <entry>' fixes it"})
        if findings:
            out[n] = findings
    return out


def action_doctor(args):
    """Advisory self-checks. Findings are JSON on stdout;
    the exit code stays 0 -- doctor reports, it does not gate."""
    data = load()
    warn_cmd_unsafe_routed(data)
    if args.name:
        targets = [require_profile(data, args.name)]
    else:
        targets = [p for p in data["profiles"]["list"]
                   if str(p.get("name", "")).startswith(PREFIX)]
    cfg_entries = _user_config_entries()
    report: dict = {}
    for p in targets:
        try:
            findings = _doctor_findings(data, p, cfg_entries)
        except SystemExit:
            # A poisoned commandline (hand-edited settings.json) dies inside
            # cmd_fields. Doctor is a self-check tool: one unreadable entry
            # becomes a finding -- it must not sink the whole report or
            # break the exit-code-0 contract (argparse help + SKILL.md).
            findings = [{"level": "warn", "check": "commandline",
                         "msg": f"commandline cannot be parsed "
                         f"({_LAST_DIE or 'unparsable'}); fix or remove the "
                         f"entry"}]
        if findings:
            report[p["name"][len(PREFIX):]] = findings
    report.update(sftp_companion_findings(
        data, args.name if args.name else None))
    print(json.dumps({"checked": len(targets), "findings": report},
                     ensure_ascii=False, indent=2))


def checked_key_arg(key: str | None) -> str | None:
    """Validate an --key value. `none` clears the identity; `wtv:<name>` must
    name an existing standalone vault key and is normalized to the on-disk
    spelling (case fixes itself instead of failing later at connect time);
    anything else is a path and passes through untouched."""
    if key is None or key == "none":
        return None
    if is_key_ref(key):
        name = key_ref_name_lenient(key)
        if name is None:
            die(f"invalid vault key reference: {key!r} (expected "
                f"'{KEY_REF_PREFIX}<name>', e.g. {KEY_REF_PREFIX}alpha)")
        name = disk_key_name(checked_key_name(name))
        if not vault_key_path(name).exists():
            die(f"no vault key named '{name}'; 'wtssh key list' shows them, "
                f"'wtssh key import {name} <file>' creates one")
        return f"{KEY_REF_PREFIX}{name}"
    return key


def resolve_jump_arg(data: dict, spec: str | None, mode: str) -> str | None:
    """The --jump value for add/edit under a jumpMode. 'preserve' (the
    default, D1) keeps a book-entry alias VERBATIM -- import's semantics: ssh
    matches the alias against the user config at runtime (F3), and a later
    `edit` must not silently rewrite the hop. 'expand' is the write-time
    resolution. Literal user@host[:port] specs are unaffected by
    the mode; 'none' still raises resolve_jump's dedicated die (it only ever
    means 'clear', in edit)."""
    if spec is None or mode == "expand" or spec == "none":
        return resolve_jump(data, spec)
    return spec


def action_add(args):
    name = checked_entry_name(args.name)
    for fld in ("user", "host", "port", "key", "jump"):
        check_cmdline_field(fld, getattr(args, fld))
    key = checked_key_arg(args.key)
    # the mutual-exclusion check (key reference vs stored passphrase) runs
    # below on the built commandline, so it also covers refs that arrive via
    # --extra; doing it on `--key` alone missed that shape.
    extra, tail = parse_extra(args.extra) or ([], [])
    if args.hidden and args.default:
        die("a hidden entry cannot be the default profile; omit --hidden "
            "or omit --default")
    with Lock():
        data = load()
        if find_profile(data, name):
            die(f"entry '{name}' already exists")
        jump = resolve_jump_arg(data, args.jump,
                                args.jump_mode or "preserve")
        guid = "{" + str(uuid.uuid4()) + "}"
        while by_guid(data, guid):  # paranoia; uuid4 collision ~impossible
            guid = "{" + str(uuid.uuid4()) + "}"
        profile = new_profile(guid, name, args.user, args.host,
                              args.port, key, jump, extra, tail,
                              args.title, hidden=bool(args.hidden))
        if args.jump_mode == "expand" and args.jump:
            # absent field == the preserve default; only record deviations.
            # A mode without a jump says nothing about anything -- do not
            # persist it.
            profile["jumpMode"] = "expand"
        # Judge key references by the LINE, not by the --key field: a ref can
        # also arrive through --extra (`--extra "-i wtv:foo"`), and the read
        # paths (list/referrers/connect/key remove/secret set) all use the line.
        # Deciding on the field alone produced entries that list called
        # vaultKey:true while WT ran a bare `ssh -i wtv:foo` (never connects).
        refs = entry_key_refs(profile["commandline"])
        for _path, refname in refs:
            if not vault_key_path(refname).exists():
                die(f"no vault key named '{refname}'; 'wtssh key list' shows "
                    f"them, 'wtssh key import {refname} <file>' creates one")
        if refs and secret_path(name).exists():
            die(f"entry '{name}' already has a stored passphrase; it cannot "
                f"also reference a vault key. Run 'wtssh secret remove {name}' "
                f"first (the key carries its own passphrase)")
        if refs:
            # only the shim understands `-i wtv:<name>`, so a key-referencing
            # entry must be routed even before it has any sealed passphrase
            ensure_shim()
            profile["commandline"] = routed_line(name, profile)
        data["profiles"]["list"].append(profile)
        if not args.hidden:
            # hidden jump hosts stay in profiles.list (so --jump / the
            # renderer can find them) but are kept out of the WT folder --
            # a folder listing would still show a hidden:true profile.
            pin_guid_in_group(data, guid)
            if args.default:
                data["defaultProfile"] = guid
        if args.jump:
            note_if_jump_on_menu(data, args.jump)
        if args.sftp:
            create_sftp_profile(data, name)
        save(data)
    out = {"ok": True, "name": name, "guid": guid,
           "hidden": bool(args.hidden), "sftp": bool(args.sftp)}
    if args.sftp:
        out["sftpGroup"] = SFTP_GROUP
    print(json.dumps(out))
    if refs:
        print(f"wtssh: entry '{name}' references vault key(s) "
              f"{', '.join(repr(n) for _p, n in refs)}; it opens with a CNG "
              f"PIN", file=sys.stderr)


def note_if_jump_on_menu(data: dict, spec: str | None) -> None:
    """stderr hint: a --jump alias that still sits on the WT menu.
    Never auto-hides (the user may have asked to open the jumper)."""
    if not spec or spec == "none":
        return
    for hop in _hop_specs(spec):
        jp = find_profile(data, hop)
        if jp is None or profile_hidden(jp):
            continue
        n = jp["name"][len(PREFIX):]
        print(f"wtssh: note: jump host '{n}' is still in the WT menu; "
              f"'wtssh edit {n} --hidden' keeps it as a hop without "
              f"listing it", file=sys.stderr)


def action_edit(args):
    vis_only = ((args.hidden or args.visible)
                and args.user is None and args.host is None
                and args.port is None and args.key is None
                and args.jump is None and args.extra is None
                and args.title is None and args.jump_mode is None
                and not args.sftp and not args.no_sftp)
    if vis_only:
        with Lock():
            data = load()
            p = require_profile(data, args.name)
            if args.hidden:
                hide_entry(data, p)
            else:
                show_entry(data, p)
            save(data)
        out = {"ok": True, "name": args.name,
               "hidden": True if args.hidden else False}
        print(json.dumps(out))
        return
    sftp_only = ((args.sftp or args.no_sftp)
                 and args.user is None and args.host is None
                 and args.port is None and args.key is None
                 and args.jump is None and args.extra is None
                 and args.title is None and args.jump_mode is None
                 and not args.hidden and not args.visible)
    if sftp_only:
        with Lock():
            data = load()
            orphan_cleaned = False
            if args.no_sftp and find_profile(data, args.name) is None:
                # An orphan companion (its ssh entry is gone -- only a
                # hand-edited settings.json produces one) must stay
                # removable without hand-editing: --no-sftp on a dead
                # name removes just the stale launcher.
                orphan_cleaned = delete_sftp_profile(data, args.name)
                changed = orphan_cleaned
            else:
                require_profile(data, args.name)
                changed = (create_sftp_profile(data, args.name)[1]
                           if args.sftp
                           else delete_sftp_profile(data, args.name))
            save(data)
        out = {"ok": True, "name": args.name, "sftp": bool(args.sftp),
               "changed": changed}
        if args.sftp:
            out["sftpGroup"] = SFTP_GROUP
        if orphan_cleaned:
            out["orphan"] = True
        print(json.dumps(out))
        return
    for fld in ("user", "host", "port", "key", "jump"):
        check_cmdline_field(fld, getattr(args, fld))
    with Lock():
        data = load()
        p = require_profile(data, args.name)
        f = cmd_fields(p)
        user = args.user if args.user is not None else f["user"]
        host = args.host if args.host is not None else f["host"]
        port = args.port if args.port is not None else f["port"]
        key = checked_key_arg(args.key) if args.key is not None else f["key"]
        if args.jump is None:
            # An explicit --jump-mode expand on its own
            # must migrate the STORED hop too -- the field must never
            # contradict the value. resolve_jump passes literals through
            # verbatim, so plain hosts are unaffected; preserve/absent keeps
            # the value untouched.
            jump = (resolve_jump(data, f["jump"])
                    if (args.jump_mode == "expand" and f["jump"])
                    else f["jump"])
        elif args.jump == "none":
            jump = None
        else:
            jump = resolve_jump_arg(data, args.jump,
                                    args.jump_mode
                                    or p.get("jumpMode", "preserve"))
        parsed = parse_extra(args.extra)
        if parsed is None:
            extra, tail = f["extra"], f["tail"]  # untouched flags survive --
            # a from-scratch rebuild would drop them
        else:
            extra, tail = parsed
        if not host:
            die("edit would leave the entry without a host; pass --host")
        line = build_commandline(user, host, port, key, jump, extra, tail)
        if entry_key_refs(line) or has_lexical_key_ref(line):
            if secret_path(args.name).exists():
                # connect unwraps the key and hands ssh ITS passphrase; a stored
                # passphrase would be silently ignored and then drift. Refuse, the
                # same way `key import` refuses the mirror-image state. The
                # lexical scan catches degraded references (a mangled or
                # cmd-poisoned `wtv:` spelling) that lenient parsing won't
                # resolve.
                die(f"entry '{args.name}' has a stored passphrase; it cannot also "
                    f"reference a vault key. Run 'wtssh secret remove "
                    f"{args.name}' first (the key carries its own passphrase)")
        routed = (secret_path(args.name).exists()
                  or bool(entry_key_refs(line)))
        if routed:
            ensure_shim()
        p["commandline"] = (routed_line(args.name, {"commandline": line})
                            if routed else line)
        if args.jump_mode == "expand":
            p["jumpMode"] = "expand"
        elif args.jump_mode == "preserve":
            p.pop("jumpMode", None)  # explicitly back to the default
        if args.title is not None:
            if args.title == "":
                p.pop("tabTitle", None)
            else:
                p["tabTitle"] = args.title
        if args.hidden:
            hide_entry(data, p)
        elif args.visible:
            show_entry(data, p)
        if args.jump and args.jump != "none":
            note_if_jump_on_menu(data, args.jump)
        if args.sftp:
            create_sftp_profile(data, args.name)
        elif args.no_sftp:
            delete_sftp_profile(data, args.name)
        save(data)
    out = {"ok": True, "name": args.name}
    if args.hidden:
        out["hidden"] = True
    elif args.visible:
        out["hidden"] = False
    if args.sftp:
        out["sftp"] = True
        out["sftpGroup"] = SFTP_GROUP
    elif args.no_sftp:
        out["sftp"] = False
    print(json.dumps(out))


def action_rename(args):
    # `old` is an existing name and stays lenient (a legacy cmd-unsafe name
    # must remain renamable -- that is the escape hatch); only `new` is strict.
    old, new = clean_name(args.old), checked_entry_name(args.new)
    sp_old, sp_new = secret_path(old), secret_path(new)
    have_secret = sp_old.exists()
    data = load()
    require_profile(data, old)
    if find_profile(data, new):
        die(f"entry '{new}' already exists")
    if have_secret and sp_new.exists():
        die(f"a sealed blob already exists at '{new}'s path (leftover from "
            f"an interrupted rename?); delete it manually first: {sp_new}")
    written: list[Path] = []
    rewrote: list[str] = []
    rewrote_sftp = False
    if have_secret:
        # Re-seal BEFORE taking the Lock: the CNG PIN dialog blocks, and a
        # 60s stall would expire the lockfile (same reasoning as
        # action_secret_set). Rename only re-wraps the secret under the same
        # TPM key, which still needs the PIN.
        #
        # Vault KEYS are deliberately NOT touched: a standalone key is its own
        # object that entries merely reference (`-i wtv:<name>`), so renaming an
        # entry neither moves nor re-seals it -- and therefore costs no PIN.
        reseat_blob(SECRET_AAD, old, new, sp_old, sp_new, f"secret '{old}'",
                    pin_text("pin_rename_secret", old=old, new=new))
        written.append(sp_new)
    with Lock():
        try:
            data = load()
            p = require_profile(data, old)
            if find_profile(data, new):
                die(f"entry '{new}' already exists")
            routed = is_routed(strict_tokens_or_die(
                p, p.get("commandline") or ""))
            p["name"] = PREFIX + new
            if routed:
                ensure_shim()
                # the embedded connect target must follow the new name; key
                # refs inside the line are name-independent and stay put
                p["commandline"] = routed_line(new, p)
            rewrote = rewrite_jump_referrers(data, old, new)
            comp = find_sftp_profile(data, old)
            if comp is not None:
                if find_sftp_profile(data, new) is not None:
                    die(f"an SFTP menu entry '{SFTP_PREFIX}{new}' already "
                        f"exists (leftover from a hand edit?); remove it "
                        f"from settings.json first")
                # the companion's commandline carries the entry name, so it
                # follows the rename (no secret blob, no key refs to move)
                comp["name"] = SFTP_PREFIX + new
                comp["commandline"] = sftp_line(new)
                rewrote_sftp = True
            save(data)
        except BaseException:
            # settings.json was never replaced, so the freshly re-sealed copy
            # is an orphan and the old blob is still the live one: drop it, or
            # the next attempt would refuse the leftover path and demand a
            # manual delete. Re-sealing is repeatable.
            drop_blobs(written)
            raise
    for f in (sp_old,):
        if f.exists():
            try:
                f.unlink()
            except OSError as e:
                print(f"wtssh: warning: could not remove old blob {f}: {e} "
                      f"-- remove it manually", file=sys.stderr)
    print(json.dumps({"ok": True, "renamed": f"{old} -> {new}",
                      "rewroteJump": rewrote, "rewroteSftp": rewrote_sftp},
                     ensure_ascii=False))


def action_remove(args):
    orphan_keys: list[Path] = []
    with Lock():
        data = load()
        p = require_profile(data, args.name)
        refs = jump_referrer_names(data, args.name)
        if refs and not args.force:
            die(f"entry '{args.name}' is the jump host for {refs}; hide it "
                f"from the menu instead ('wtssh edit {args.name} --hidden') "
                f"or pass --force to delete it and leave those -J names "
                f"dangling")
        guid = p["guid"]
        data["profiles"]["list"].remove(p)
        # the sftp:<name> FileZilla menu entry is a companion of THIS entry:
        # it must not outlive it (no orphan launcher in the WT menu)
        removed_sftp = delete_sftp_profile(data, args.name)
        sp = secret_path(args.name)
        sp_exists = sp.exists()
        # A standalone vault key is its own object: removing the entry must not
        # delete a key that merely shares its name (another entry, or a
        # hand-written line, may reference it). Report it instead.
        orphan_keys = [f for f in (vault_key_path(args.name),)
                       if f.exists()]
        # a guid can be referenced from ANY folder (the same entry may be
        # pinned in several groups), so sweep them all -- not just ours
        sweep_guid_from_folders(data, guid)
        if data.get("defaultProfile") == guid:
            data["defaultProfile"] = resolve_fallback_default(data)
        save(data)
        # the sealed blob is deleted only after the settings write succeeded:
        # a failed save then leaves entry + secret consistent (settings.json
        # and .bak untouched), instead of an entry whose passphrase is gone.
        if sp_exists:
            try:
                sp.unlink()
            except OSError as e:
                print(f"wtssh: warning: could not remove secret blob {sp}: "
                      f"{e} -- remove it manually", file=sys.stderr)
    print(json.dumps({"ok": True, "removed": args.name,
                      "removedSftp": removed_sftp,
                      "keptKeys": [str(f) for f in orphan_keys]},
                     ensure_ascii=False))
    if orphan_keys:
        print(f"wtssh: vault key files named after '{args.name}' were kept "
              f"(they are independent objects): "
              f"{', '.join(str(f) for f in orphan_keys)} -- "
              f"'wtssh key list' shows their users, 'wtssh key remove "
              f"{args.name}' deletes one", file=sys.stderr)


def action_move(args):
    with Lock():
        data = load()
        p = require_profile(data, args.name)
        if profile_hidden(p):
            die(f"entry '{args.name}' is hidden from the menu; "
                f"'wtssh edit {args.name} --visible' first")
        guid = p["guid"]
        entries = get_folder(data, create=True)["entries"]
        me = next((e for e in entries if e.get("profile") == guid), None)
        if me is None:
            me = {"type": "profile", "icon": None, "profile": guid}
        else:
            entries.remove(me)
        if args.top:
            entries.insert(0, me)
        elif args.bottom:
            entries.append(me)
        elif args.before or args.after:
            ref = require_profile(data, args.before or args.after)
            idx = next((i for i, e in enumerate(entries)
                        if e.get("profile") == ref["guid"]), None)
            if idx is None:
                die(f"'{ref['name'][len(PREFIX):]}' is not in the {GROUP} group")
            entries.insert(idx + 1 if args.after else idx, me)
        else:
            entries.append(me)
        # the sftp:<name> companion stays adjacent only when it is pinned
        # in THIS folder (SFTP_GROUP == GROUP). Default pin is the sftp
        # group, so a move of the ssh row does not drag it over.
        comp = find_sftp_profile(data, args.name)
        if comp is not None:
            centry = next((e for e in entries
                           if e.get("profile") == comp.get("guid")), None)
            if centry is not None:
                entries.remove(centry)
                me_idx = next((i for i, e in enumerate(entries)
                               if e.get("profile") == guid), None)
                entries.insert(me_idx + 1 if me_idx is not None
                               else len(entries), centry)
        save(data)
    print(json.dumps({"ok": True, "moved": args.name}))


def action_get_default(args):
    data = load()
    p = by_guid(data, data.get("defaultProfile", ""))
    if p is None:
        print(data.get("defaultProfile"))
        return
    name = p["name"]
    print(name[len(PREFIX):] if name.startswith(PREFIX) else name)


def action_set_default(args):
    with Lock():
        data = load()
        p = require_profile(data, args.name)
        if profile_hidden(p):
            die(f"entry '{args.name}' is hidden from the menu; "
                f"'wtssh edit {args.name} --visible' first")
        data["defaultProfile"] = p["guid"]
        save(data)
    print(json.dumps({"ok": True, "default": args.name}))


# ------------------------------------------------------------------ import

# ssh_config keywords that accumulate across repetitions; every other
# keyword keeps its first obtained value (ssh_config(5) general rule).
ACCUMULATING_KW = frozenset((
    "identityfile", "certificatefile", "localforward", "remoteforward",
    "dynamicforward", "sendenv", "setenv", "canonicaldomains",
))


# Keywords whose value is the rest of the line, verbatim. OpenSSH never
# treats '#' inside them as a comment (verified against 9.5p2:
# `ProxyCommand echo hi # stay` keeps the trailing '# stay' in -G output),
# so the comment stripper below must leave them alone.
REST_OF_LINE_KW = frozenset(("proxycommand", "remotecommand", "localcommand"))


def _strip_ssh_comment(kw: str, value: str) -> str:
    """Strip ssh_config inline comments from a keyword's value, matching
    OpenSSH 9.5p2 semantics (all verified empirically with `ssh -G -F`):

    - an unquoted '#' that STARTS A TOKEN begins a comment running to end
      of line ('HostName ex.com # note' -> 'ex.com'; 'Host t3 # c' has one
      alias, not three);
    - a '#' inside a token or inside a quoted run is literal
      ('ex#ample.com', '"ex #2.com"' stay intact);
    - ProxyJump: the jump-spec parser stops at a '#' ANYWHERE in the value
      ('lit#x.com' connects to 'lit'), so cut there unconditionally;
    - rest-of-line keywords (ProxyCommand et al.) never see comments.

    kw must be lower-case; the caller keeps the original spelling.
    """
    if kw in REST_OF_LINE_KW:
        return value
    if kw == "proxyjump":
        return value.split("#", 1)[0]
    cur = ""
    quoted = False
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] == '"':
            cur += c + value[i + 1]
            i += 2
            continue
        if c == '"':
            quoted = not quoted
            cur += c
            i += 1
            continue
        if c == "#" and not quoted and (not cur or cur[-1].isspace()):
            break
        cur += c
        i += 1
    return cur


def _kv(line: str) -> tuple[str, str] | None:
    """Split an ssh_config line into (keyword, value); None for blanks and
    comments. ssh accepts both 'Key Value' and 'Key=Value'. Inline comments
    are stripped per ssh's own rules (see _strip_ssh_comment) -- otherwise
    'HostName ex.com # note' would bake the comment into the host field
    and 'Host t3 # c' would create junk aliases named '#' and 'c'."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    m = re.match(r"([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$", s)
    if m:
        kw, val = m.group(1), m.group(2)
    else:
        parts = s.split(None, 1)
        kw = parts[0]
        val = parts[1] if len(parts) > 1 else ""
    return kw, _strip_ssh_comment(kw.lower(), val).strip()


def _split_value(value: str, strict: bool = False) -> list[str]:
    """Whitespace-separated value list with quoting (Host aliases,
    IdentityFile, and --extra).

    NOT shlex(posix=True): on Windows an IdentityFile value is a backslash
    path, and POSIX mode eats every backslash as an escape ('C:\\Users\\x'
    -> 'C:Usersx'). ssh itself keeps backslashes and only honours '"' (a
    quoted run may carry spaces); '\\"' is a literal quote, which means a
    path ending in a backslash right before a quote ('C:\\x\\"q"') loses
    that backslash -- the same way ssh's own tokenizer behaves.

    strict=True raises ValueError on an unterminated double quote instead
    of silently swallowing the rest of the string (--extra: a mis-split
    option is worse than a loud refusal)."""
    out: list[str] = []
    cur = ""
    quoted = False
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] == '"':
            cur += '"'
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        elif c.isspace() and not quoted:
            if cur:
                out.append(cur)
                cur = ""
        else:
            cur += c
        i += 1
    if quoted and strict:
        raise ValueError("unterminated double quote")
    if cur:
        out.append(cur)
    return out


def _add_extra(values: dict, kw: str, pair: tuple[str, str]) -> None:
    """Collect an unmodeled keyword as an '-o Key=Value' pair. ssh uses the
    first obtained value unless the option is documented as accumulating
    (multiple forwardings, SendEnv/SetEnv, ...), so repeated keywords are
    dropped instead of both being emitted (command-line -o is last-wins)."""
    extra = values.setdefault("extra", [])
    if kw not in ACCUMULATING_KW and any(k.lower() == kw for k, _ in extra):
        return
    extra.append(pair)


def parse_ssh_config(text: str, base: Path, _seen: frozenset = frozenset(),
                     depth: int = 0) -> list[dict]:
    """Parse an OpenSSH client config into wtssh entry dicts.

    Only the keywords wtssh models become fields (HostName/User/Port/
    ProxyJump/IdentityFile); every other keyword survives as an
    '-o Key=Value' token, so ssh itself still applies it. Wildcard aliases,
    'Host *' and 'Match' blocks are skipped: an imported entry is one
    concrete host, not a rule. Include files are expanded in place."""
    if depth > 8:
        return []
    out: list[dict] = []
    aliases: list[str] = []
    values: dict = {}

    def flush():
        if not aliases:
            return
        for alias in aliases:
            ids = values.get("identityfile") or []
            extra: list[str] = []
            for path in ids[1:]:
                # ssh allows repeated -i; as an -o token it stays inside
                # `extra` (an -i there would be re-read as the key field)
                extra += ["-o", shquote(f"IdentityFile={os.path.expanduser(path)}")]
            for opt, val in values.get("extra", []):
                extra += ["-o", shquote(f"{opt}={val}")]
            out.append({
                "name": alias,
                "user": values.get("user"),
                "host": values.get("hostname") or alias,
                "port": values.get("port"),
                "key": os.path.expanduser(ids[0]) if ids else None,
                "jump": values.get("proxyjump"),
                "extra": extra,
            })

    for raw in text.splitlines():
        kv = _kv(raw)
        if kv is None:
            continue
        kw, val = kv[0].lower(), kv[1]
        if kw == "host":
            flush()
            aliases, values = [], {}
            for alias in _split_value(val):
                if any(c in alias for c in "*?!"):
                    continue
                if name_is_usable(alias) and alias not in aliases:
                    aliases.append(alias)
            continue
        if kw == "match":
            # Match is not a host block and cannot be expressed as an -o
            # option; skip everything up to the next Host line
            flush()
            aliases, values = [], {}
            continue
        if kw == "include":
            # Include is position-independent in ssh_config (it is expanded
            # while reading, outside Host matching), so it is honoured even
            # before the first Host block -- that is where it usually sits.
            for inc in _split_value(val):
                pat = os.path.expanduser(inc)
                if not os.path.isabs(pat):
                    pat = str(base / pat)
                for f in sorted(glob.glob(pat)):
                    fp = Path(f)
                    if fp in _seen or not fp.is_file():
                        continue
                    try:
                        sub = fp.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    out += parse_ssh_config(sub, fp.parent,
                                            _seen | {fp}, depth + 1)
            continue
        if not aliases:
            continue  # keyword outside any Host block: global defaults, skip
        if kw in ("hostname", "user", "proxyjump"):
            # ssh: "the first obtained value for each parameter is used"
            values.setdefault(kw, val if kw != "proxyjump"
                              else val.replace(" ", ""))
        elif kw == "port":
            if val.isdigit():
                values.setdefault("port", val)
            else:
                _add_extra(values, kw, ("Port", val))
        elif kw == "identityfile":
            values.setdefault("identityfile", []).extend(_split_value(val))
        else:
            # lossless: ssh re-applies it from the command line
            _add_extra(values, kw, (kv[0], val))
    flush()
    return out


def action_import(args):
    global _LAST_DIE
    src = Path(args.ssh_config).expanduser()
    if not src.is_file():
        die(f"ssh config not found: {src}")
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        die(f"cannot read {src}: {e}")
    parsed = parse_ssh_config(text, src.parent)
    imported, skipped = [], []
    with Lock():
        data = load()
        folder = get_folder(data, create=True)
        for item in parsed:
            name = item["name"]
            if find_profile(data, name):
                skipped.append({"name": name, "reason": "an entry with that "
                                "name already exists"})
                continue
            guid = "{" + str(uuid.uuid4()) + "}"
            while by_guid(data, guid):
                guid = "{" + str(uuid.uuid4()) + "}"
            # Same poison the CLI check_cmdline_field refuses, arriving via
            # ssh config values instead of argv (including -o values built
            # from config keywords). build_commandline's round-trip backstop
            # dies for those -- the only die reachable inside new_profile --
            # so convert it into THIS entry's skip instead of aborting the
            # batch (import skips loudly per entry).
            try:
                profile = new_profile(guid, name, item["user"], item["host"],
                                      item["port"], item["key"], item["jump"],
                                      item["extra"], None)
            except SystemExit:
                # die() already printed the offending line to stderr; surface
                # its message as this entry's skip reason instead of a static
                # text (argparse SystemExits carry no die message -- those
                # keep the fallback).
                reason = _LAST_DIE or ("the built ssh command cannot be "
                                       "round-tripped (embedded quote or "
                                       "trailing backslash in a config "
                                       "value); see the wtssh: error line "
                                       "above")
                _LAST_DIE = None
                skipped.append({"name": name, "reason": reason})
                continue
            # an ssh config can spell a vault key as `IdentityFile wtv:foo`.
            # Those entries need the shim exactly like `add --key wtv:` does,
            # otherwise WT runs `ssh -i wtv:foo` and ssh treats the reference as
            # a file name.
            refs = entry_key_refs(profile["commandline"])
            if refs and secret_path(name).exists():
                skipped.append({"name": name, "reason": "a stored passphrase "
                                "already exists for that name and the config "
                                "also references a vault key"})
                continue
            if refs:
                bad = cmd_risky_payload_chars(profile["commandline"])
                if bad:
                    # a hostile ssh config can carry cmd metacharacters in
                    # HostName/User/keyword values; such a line cannot be
                    # routed, so skip it loudly instead of aborting the run
                    skipped.append({"name": name, "reason": "the ssh command "
                                    "carries cmd metacharacters "
                                    f"{' '.join(repr(c) for c in bad)} and "
                                    "cannot be routed (vault keys referenced)"})
                    continue
                ensure_shim()
                profile["commandline"] = routed_line(name, profile)
                missing = [n for path, n in refs if not path.exists()]
                if missing:
                    print(f"wtssh: warning: imported '{name}' references "
                          f"vault key(s) {', '.join(repr(m) for m in missing)} "
                          f"that do not exist yet ('wtssh key list')",
                          file=sys.stderr)
            data["profiles"]["list"].append(profile)
            folder["entries"].append(
                {"type": "profile", "icon": None, "profile": guid})
            imported.append(name)
        if imported:
            save(data)
    print(json.dumps({"imported": imported, "skipped": skipped},
                     ensure_ascii=False))


# ------------------------------------------------------- filezilla bridge

# FileZilla client command line (verified against the 3.68 sources; unchanged
# in the 3.69 line): `filezilla.exe -c <site-path>` connects straight to a
# Site Manager site, while `-s` merely OPENS the Site Manager dialog. The
# site path is the literal root `0` (the user's sitemanager.xml; `1` would
# be fzdefaults.xml) plus `/`-separated Folder/Server name segments matched
# case-sensitively; `\` and `/` inside a segment escape as `\\` and `\/`
# (src/commonui/site_manager.cpp). Every launch is a fresh process that
# re-reads sitemanager.xml from disk under FileZilla's own inter-process
# mutex before connecting: sync-then-launch is safe, and there is no
# single-instance forwarding. The sftp:// URL form cannot carry key files
# and would put a password into argv, so this bridge is site-based only.

FZ_LOGON_ASK = 2   # FileZilla prompts for the password at connect time
FZ_LOGON_KEY = 5   # SFTP public-key auth via the <Keyfile> path


def fz_site_file() -> Path:
    env = os.environ.get("WTSSH_FZ_SITEMANAGER")
    if env:  # drill hook: test against a copy, never the live site list
        return Path(env)
    appdata = os.environ.get("APPDATA")
    if not appdata:
        die("APPDATA is not set; cannot locate FileZilla's sitemanager.xml")
    return Path(appdata) / "FileZilla" / "sitemanager.xml"


def fz_lock_path() -> Path:
    p = fz_site_file()
    return p.with_name(p.name + ".wtssh.lock")


def filezilla_exe(args) -> str:
    """--filezilla beats $WTSSH_FILEZILLA beats the default install dirs.
    An explicitly given path must exist -- silently falling through to the
    other candidates would replace the user's intent."""
    explicit = getattr(args, "filezilla", None)
    if explicit and not Path(explicit).is_file():
        die(f"--filezilla path does not exist: {explicit}")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("WTSSH_FILEZILLA")
    if env:
        candidates.append(Path(env))
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(var)
        if base:
            candidates.append(Path(base) / "FileZilla FTP Client"
                              / "filezilla.exe")
    for cand in candidates:
        if cand.is_file():
            return str(cand)
    found = find_bin("filezilla")  # PATH with the CWD excluded
    if found:
        return found
    die("filezilla.exe not found (looked at --filezilla, $WTSSH_FILEZILLA, "
        "the default install dirs and PATH); pass --filezilla PATH")


def fz_escape_segment(segment: str) -> str:
    """FileZilla site-path escapement (site_manager.cpp EscapeSegment)."""
    return segment.replace("\\", "\\\\").replace("/", "\\/")


def fz_element_name(el) -> str:
    """A Folder/Server element's name: <Name> child text, or the element's
    own text (folders carry their name as text in FileZilla's dialect)."""
    if el.tag not in ("Folder", "Server", "Bookmark"):
        return ""
    name_el = el.find("Name")
    if name_el is not None and (name_el.text or "").strip():
        return name_el.text.strip()
    return (el.text or "").strip()


def fz_find_folder(servers, name: str):
    for child in servers:
        if child.tag == "Folder" and fz_element_name(child) == name:
            return child
    return None


def fz_find_server(folder, name: str):
    for child in folder:
        if child.tag == "Server" and fz_element_name(child) == name:
            return child
    return None


def fz_set_child(server, tag: str, value) -> bool:
    """Set <tag>value</tag>; True when this wrote anything."""
    el = server.find(tag)
    text = str(value)
    if el is None:
        el = ET.SubElement(server, tag)
        el.text = text
        return True
    if (el.text or "") != text:
        el.text = text
        return True
    return False


def fz_new_server(name: str):
    """A fresh <Server> with the fields wtssh does not manage, in FileZilla's
    own child order. Managed fields (Host/Port/User/Keyfile/Logontype) are
    appended by fz_sync_server; FileZilla reads children by tag, order is
    cosmetic."""
    server = ET.Element("Server")
    for tag, value in (("Protocol", 1),      # 1 = SFTP
                       ("Type", 0),
                       ("PasvMode", "MODE_DEFAULT"),
                       ("EncodingType", "Auto"),
                       ("BypassProxy", 0),
                       ("Name", name),
                       ("SyncBrowsing", 0),
                       ("DirectoryComparison", 0)):
        el = ET.SubElement(server, tag)
        el.text = str(value)
    return server


def fz_load_tree(path: Path):
    """Parse sitemanager.xml, or seed a minimal one when FileZilla has never
    saved a site. Never repairs a corrupt file: die and point at the
    backup. A seeded root claims a current-ish version because every field
    we write is current-schema; FileZilla's upgrade path only ever walks
    forward and would find nothing to do."""
    if not path.exists():
        if not path.parent.is_dir():
            die(f"{path.parent} does not exist; install FileZilla (and run "
                "it once) before opening host-book entries with it")
        root = ET.Element("FileZilla3", {"version": "3.69.0",
                                         "platform": "windows"})
        root.append(ET.Element("Servers"))
        return ET.ElementTree(root)
    try:
        tree = ET.parse(path)
    except OSError as e:
        die(f"cannot read {path}: {e}")
    except ET.ParseError as e:
        die(f"cannot parse {path}: {e}; FileZilla's site list is corrupt -- "
            f"fix it in FileZilla or restore {path}.wtssh.bak first")
    root = tree.getroot()
    if root.tag != "FileZilla3" or root.find("Servers") is None:
        die(f"{path} is not a FileZilla3 site list; not touching it")
    return tree


def fz_save_tree(tree, path: Path) -> None:
    """Backup-then-atomic-replace, with a parse validation of what we ship."""
    ET.indent(tree, space="\t")
    payload = ('<?xml version="1.0"?>\n'
               + ET.tostring(tree.getroot(), encoding="unicode")
               ).encode("utf-8")
    try:
        ET.fromstring(payload)  # defensive: never replace good XML with bad
    except ET.ParseError as e:
        die(f"internal error: generated invalid site XML: {e}", 2)
    try:
        if path.exists():
            atomic_write(path.with_name(path.name + ".wtssh.bak"),
                         path.read_bytes())
        atomic_write(path, payload)
    except OSError as e:
        die(f"cannot write {path}: {e}")


FZ_PROXY_KEYS = ("Proxy type", "Proxy host", "Proxy port",
                 "Proxy user", "Proxy password")
FZ_SOCKS5 = "2"   # the "Proxy type" ordinal. The settings page's dropdown
                  # order is None, HTTP/1.1 CONNECT, SOCKS4, SOCKS5 (binary
                  # string order in filezilla.exe 3.69.5), and there is no
                  # separate enable flag: type 0 (None) IS off. Verified
                  # against a live config pointing at an ssh -D listener.


def fz_config_file() -> Path:
    env = os.environ.get("WTSSH_FZ_FILEZILLAXML")
    if env:  # drill hook: test against a copy, never the live settings
        return Path(env)
    appdata = os.environ.get("APPDATA")
    if not appdata:
        die("APPDATA is not set; cannot locate FileZilla's filezilla.xml")
    return Path(appdata) / "FileZilla" / "filezilla.xml"


def fz_config_load(path: Path):
    """Parse filezilla.xml, or seed a minimal one when FileZilla has never
    saved settings. Never repairs a corrupt file: die and point at the
    backup (same discipline as fz_load_tree). Returns (tree, existed)."""
    if not path.exists():
        root = ET.Element("FileZilla3", {"version": "3.69.0",
                                         "platform": "windows"})
        root.append(ET.Element("Settings"))
        return ET.ElementTree(root), False
    try:
        tree = ET.parse(path)
    except OSError as e:
        die(f"cannot read {path}: {e}")
    except ET.ParseError as e:
        die(f"cannot parse {path}: {e}; FileZilla's settings are corrupt "
            f"-- fix them in FileZilla or restore {path}.wtssh.bak first")
    root = tree.getroot()
    if root.tag != "FileZilla3" or root.find("Settings") is None:
        die(f"{path} is not a FileZilla3 settings file; not touching it")
    return tree, True


def fz_config_save(tree, path: Path) -> None:
    """fz_save_tree's discipline for filezilla.xml: backup-then-atomic-
    replace, with a parse validation of what we ship."""
    ET.indent(tree, space="\t")
    payload = ('<?xml version="1.0"?>\n'
               + ET.tostring(tree.getroot(), encoding="unicode")
               ).encode("utf-8")
    try:
        ET.fromstring(payload)  # defensive: never replace good XML with bad
    except ET.ParseError as e:
        die(f"internal error: generated invalid settings XML: {e}", 2)
    try:
        if path.exists():
            atomic_write(path.with_name(path.name + ".wtssh.bak"),
                         path.read_bytes())
        atomic_write(path, payload)
    except OSError as e:
        die(f"cannot write {path}: {e}")


def fz_proxy_apply(port: int, user: str, password: str) -> dict:
    """Point FileZilla's GENERIC proxy at this session's authenticated
    local SOCKS5 gate (socks_gate_serve): SOCKS5 with the per-session
    RFC 1929 user/password, so a same-machine other-user process cannot
    ride the tunnel anonymously any more. FileZilla reads filezilla.xml
    once per launch, so the write must land before Popen; SFTP honors the
    generic proxy through fzsftp, and wtssh-created sites carry
    BypassProxy=0 so they ride it. Returns the exact previous state of the
    managed keys for fz_proxy_restore (a stored proxy password is only
    ever held in memory and written back to the file it came from; the
    session credentials themselves are never logged and never enter the
    JSON result -- captured stdout is a transcript). May die on a
    corrupt/unwritable file -- the tunnel process is cleaned up by
    action_filezilla's finally belt."""
    path = fz_config_file()
    tree, _existed = fz_config_load(path)
    settings = tree.getroot().find("Settings")
    saved = {"keys": {}}
    for key in FZ_PROXY_KEYS:
        el = settings.find(f'Setting[@name="{key}"]')
        saved["keys"][key] = None if el is None else (el.text or "")
    for key, value in (("Proxy type", FZ_SOCKS5),
                       ("Proxy host", "127.0.0.1"),
                       ("Proxy port", str(port)),
                       ("Proxy user", user),
                       ("Proxy password", password)):
        el = settings.find(f'Setting[@name="{key}"]')
        if el is None:
            el = ET.SubElement(settings, "Setting", {"name": key})
        el.text = value
    fz_config_save(tree, path)
    return saved


def fz_proxy_restore(saved: dict | None) -> None:
    """Write back exactly what fz_proxy_apply saw: previous values
    verbatim, previously-absent keys absent again (a seeded file that never
    existed before stays as an inert Settings-only file). Called once OUR
    FileZilla instance has exited -- FileZilla saves settings on its own
    exit, so restoring earlier would race its final write. A concurrent
    second instance exiting later still wins (documented limitation)."""
    if not saved:
        return
    path = fz_config_file()
    tree, _ = fz_config_load(path)
    settings = tree.getroot().find("Settings")
    changed = False
    for key, prev in saved["keys"].items():
        el = settings.find(f'Setting[@name="{key}"]')
        if prev is None:
            if el is not None:
                settings.remove(el)
                changed = True
        else:
            if el is None:
                el = ET.SubElement(settings, "Setting", {"name": key})
            if (el.text or "") != prev:
                el.text = prev
                changed = True
    if changed:
        fz_config_save(tree, path)


# ------------------------------------------------- socks gate (--tunnel)
#
# The merged-path SOCKS listener used to BE `ssh -D`: anonymous, so any
# process of ANY local user could ride the tunnel for its whole lifetime
# (full SOCKS via the jump chain). The gate fronts it: FileZilla dials the
# gate with a per-session RFC 1929 username/password (fz_proxy_apply writes
# them into filezilla.xml, whose profile ACL only the current user reads),
# the gate re-originates the request as an anonymous SOCKS5 client of
# `ssh -D` on a SECOND, private loopback port, and everything else is
# refused. The gate parses just enough SOCKS5 to authenticate and frame --
# the CONNECT target bytes are relayed verbatim, so whatever `ssh -D`
# accepts (IPv4 / domain / IPv6) rides unchanged, and the `-L` fallback
# stays untouched (raw TCP has no hook for credentials).

SOCKS_GATE_VER = 5
SOCKS_AUTH_VER = 1              # RFC 1929 subnegotiation version byte
SOCKS_METHOD_NOAUTH = 0x00
SOCKS_METHOD_USERPASS = 0x02
SOCKS_METHOD_NONE = 0xFF        # "no acceptable methods" (greeting reply)
SOCKS_CMD_CONNECT = 0x01
SOCKS_REP_OK = 0x00
SOCKS_REP_GENERAL = 0x01        # general SOCKS server failure
SOCKS_REP_HOST_UNREACH = 0x04   # upstream dial timed out
SOCKS_REP_REFUSED = 0x05
SOCKS_REP_CMD_NOTSUP = 0x07
SOCKS_REP_ATYP_NOTSUP = 0x08
MIB_TCP_STATE_LISTEN = 2
SOCKS_GATE_HANDSHAKE_TIMEOUT = 15.0   # per-frame budget while handshaking
SOCKS_GATE_UPSTREAM_TIMEOUT = 10.0    # `ssh -D` dial + CONNECT round-trip
# ATYP -> fixed address length; the domain type (0x03) is length-prefixed
# instead, which _socks_atyp_addr handles specially. Anything else is
# refused with REP 0x08.
_SOCKS_ATYP_LEN = {0x01: 4, 0x03: None, 0x04: 16}


def _socks_read_exact(conn: socket.socket, n: int) -> bytes:
    """recv exactly n bytes; EOF mid-frame raises ConnectionError so every
    caller fails closed instead of treating a short read as data."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def _socks_atyp_addr(conn: socket.socket, atyp: int) -> bytes:
    """One SOCKS5 address field, framed by its ATYP: fixed-width for
    IPv4/IPv6, one length byte + name for a domain. The returned bytes are
    exactly what goes back on the wire, so a domain replay needs no
    parse/format round-trip."""
    if atyp == 0x03:
        ln = _socks_read_exact(conn, 1)[0]
        if ln == 0:
            raise ConnectionError("empty domain name")
        return bytes((ln,)) + _socks_read_exact(conn, ln)
    n = _SOCKS_ATYP_LEN.get(atyp)
    if n is None:
        raise ConnectionError(f"unsupported ATYP {atyp:#04x}")
    return _socks_read_exact(conn, n)


def _socks_reply(conn: socket.socket, rep: int) -> None:
    """The only reply the gate composes itself: BND.ATYP=IPv4 with an
    all-zero BND.ADDR/BND.PORT -- a relay's bind address is meaningless to
    the client, and upstream replies carry only the REP code forward."""
    conn.sendall(bytes((SOCKS_GATE_VER, rep, 0x00,
                        0x01, 0, 0, 0, 0, 0x00, 0x00)))


def _socks_drain_close(conn: socket.socket, grace: float = 0.5) -> None:
    """Retire a (typically refused) client connection without a reset:
    the reply went out already, so half-close the send side, swallow
    whatever the client still had in flight (bounded by the grace
    timeout), and only then close. A bare close() over unread receive
    data makes Windows send RST, which can discard the just-sent reply
    bytes at the peer before it reads them."""
    try:
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    try:
        conn.settimeout(grace)
        while conn.recv(4096):
            pass
    except OSError:
        pass
    finally:
        conn.close()


def _tcp_listen_owner(port: int) -> int | None:
    """Owning PID of whatever holds a LISTEN on 127.0.0.1:<port>, read from
    the kernel TCP table (GetExtendedTcpTable -- the same rows netstat -ano
    shows). None means "no such row right now", "non-Windows", or "the
    table could not be read" -- that last case is audited (verbose),
    because it is a genuine cannot-verify. Callers treat None as proceed:
    the ownership check is defense in depth on top of the RFC 1929 auth,
    and both no-row (ssh has not bound yet) and non-Windows are legitimate
    proceed states."""
    if sys.platform != "win32":
        return None
    import ctypes

    iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True)
    # explicit layouts: MIB_TCPROW_OWNER_PID is six DWORDs, the table is a
    # DWORD count followed by the variable-length row array (the buffer is
    # allocated by size and cast, so the array's real length is never
    # expressed in the type).
    class _Row(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in
                    ("dwState", "dwLocalAddr", "dwLocalPort",
                     "dwRemoteAddr", "dwRemotePort", "dwOwningPid")]

    iphlp.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    iphlp.GetExtendedTcpTable.restype = ctypes.c_uint32
    TCP_TABLE_OWNER_PID_ALL = 5   # every state, rows carry dwOwningPid
    AF_INET = 2
    size = ctypes.c_uint32(16 * 1024)
    for _ in range(3):            # grow once or twice if a flush lands between
        buf = ctypes.create_string_buffer(size.value)
        rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), 0, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0)
        if rc == 0:
            break
        if rc != 122:             # ERROR_INSUFFICIENT_BUFFER: retry with size
            audit_log("verbose", f"socks gate: cannot read the TCP table "
                                 f"(GetExtendedTcpTable rc={rc})")
            return None
    else:
        audit_log("verbose", "socks gate: TCP table size never settled; "
                             "cannot verify the private port owner")
        return None
    count = ctypes.c_uint32.from_buffer_copy(buf[0:4]).value
    row_at, row_len = 4, ctypes.sizeof(_Row)
    # dwLocalPort is the port in NETWORK byte order inside the DWORD: the
    # low 16 bits hold the byte-swapped value on little-endian.
    port_nbo = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr_loopback = 0x0100007F          # 127.0.0.1, network byte order
    for i in range(count):
        row = _Row.from_buffer_copy(
            buf[row_at + i * row_len:row_at + (i + 1) * row_len])
        if (row.dwState == MIB_TCP_STATE_LISTEN
                and row.dwLocalAddr == addr_loopback
                and (row.dwLocalPort & 0xFFFF) == port_nbo):
            return row.dwOwningPid
    return None


def _socks_gate_check_owner(priv_port: int, tunnel_pid: int | None) -> str | None:
    """Anti-squat guard for the private port: fz_pick_port still uses the
    bind-probe-then-close pattern (ssh cannot inherit a listening fd), so
    the close-rebind window is real. If a listener row exists and its owner
    is not OUR tunnel process, relaying would feed authenticated traffic to
    a squatter -- refuse. Returns a short refusal reason or None to proceed;
    "no listener yet" is not a refusal (ssh binds only after the chain
    authenticates, and the upstream dial then fails loudly on its own).
    A cannot-verify None from _tcp_listen_owner proceeds too (audited
    there): this check is defense in depth behind the RFC 1929 auth,
    never the primary control."""
    owner = _tcp_listen_owner(priv_port)
    if owner is None:
        return None
    if tunnel_pid is None:
        return f"private port has no tunnel owner (held by pid {owner})"
    if owner != tunnel_pid:
        return (f"private port held by pid {owner}, "
                f"not the tunnel process {tunnel_pid}")
    return None


def _socks_upstream_request(priv_port: int, atyp: int, addr: bytes,
                            port_bytes: bytes) -> tuple[socket.socket, int]:
    """Dial the private `ssh -D` port as an anonymous SOCKS5 client and run
    the CONNECT round-trip with the client's target bytes replayed
    verbatim. Returns (socket, upstream REP); the caller closes the socket
    unless REP is 0 (and owns it either way)."""
    up = socket.socket()
    try:
        up.settimeout(SOCKS_GATE_UPSTREAM_TIMEOUT)
        up.connect(("127.0.0.1", priv_port))
        up.sendall(bytes((SOCKS_GATE_VER, 1, SOCKS_METHOD_NOAUTH)))
        head = _socks_read_exact(up, 2)
        if head[0] != SOCKS_GATE_VER or head[1] != SOCKS_METHOD_NOAUTH:
            raise ConnectionError("upstream refused the anonymous method")
        up.sendall(bytes((SOCKS_GATE_VER, SOCKS_CMD_CONNECT, 0x00, atyp))
                   + addr + port_bytes)
        head = _socks_read_exact(up, 4)
        if head[0] != SOCKS_GATE_VER:
            raise ConnectionError("bad upstream reply version")
        rep = head[1]
        _socks_atyp_addr(up, head[3])     # drain BND.ADDR (framed by ATYP)
        _socks_read_exact(up, 2)          # drain BND.PORT
        return up, rep
    except BaseException:
        up.close()
        raise


def _socks_relay(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional byte pump until either direction ends. FileZilla-sized
    volumes and daemon threads keep a thread per direction plenty; a
    half-close is propagated with shutdown(WR) so SFTP's own EOF timing
    survives the relay."""
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join()


def _socks_gate_conn(conn: socket.socket, priv_port: int, user: str,
                     password: str, tunnel_pid: int | None) -> None:
    """One client connection: greet, authenticate (constant-time compares),
    read the CONNECT, then hand the bytes to the anonymous upstream.
    Fail-closed everywhere: a protocol surprise, an auth miss or an
    ownership mismatch closes the client -- the only messages the client
    ever sees are well-formed SOCKS5 replies."""
    peer = "?"
    up = None
    try:
        peer = "%s:%s" % conn.getpeername()
        conn.settimeout(SOCKS_GATE_HANDSHAKE_TIMEOUT)
        # -- greeting: user/pass is the only method this listener exists
        #    to offer; an anonymous-only client gets 0xFF and a log line
        ver = _socks_read_exact(conn, 1)[0]
        if ver != SOCKS_GATE_VER:
            raise ConnectionError(f"bad SOCKS version {ver:#04x}")
        nmethods = _socks_read_exact(conn, 1)[0]
        methods = set(_socks_read_exact(conn, nmethods))
        if SOCKS_METHOD_USERPASS not in methods:
            # a method refusal is a 2-byte reply (RFC 1928), not the
            # 10-byte CONNECT reply shape
            conn.sendall(bytes((SOCKS_GATE_VER, SOCKS_METHOD_NONE)))
            audit_log("verbose", f"socks gate: refused {peer} (no "
                                 f"user/pass method offered)")
            return
        conn.sendall(bytes((SOCKS_GATE_VER, SOCKS_METHOD_USERPASS)))
        # -- RFC 1929 username/password
        head = _socks_read_exact(conn, 2)          # VER ULEN
        if head[0] != SOCKS_AUTH_VER:
            raise ConnectionError("bad auth subnegotiation")
        uname = _socks_read_exact(conn, head[1])
        plen = _socks_read_exact(conn, 1)[0]
        passwd = _socks_read_exact(conn, plen)
        ok = (hmac.compare_digest(uname, user.encode("ascii"))
              and hmac.compare_digest(passwd, password.encode("ascii")))
        conn.sendall(bytes((SOCKS_AUTH_VER, 0x00 if ok else 0x01)))
        if not ok:
            audit_log("verbose", f"socks gate: auth failed for {peer}")
            return
        # -- CONNECT request (target bytes validated for framing only)
        head = _socks_read_exact(conn, 4)          # VER CMD RSV ATYP
        if head[0] != SOCKS_GATE_VER:
            raise ConnectionError("bad request version")
        cmd, atyp = head[1], head[3]
        if cmd != SOCKS_CMD_CONNECT:
            _socks_reply(conn, SOCKS_REP_CMD_NOTSUP)
            audit_log("verbose", f"socks gate: refused {peer} (only "
                                 f"CONNECT, got {cmd:#04x})")
            return
        if atyp not in _SOCKS_ATYP_LEN:
            _socks_reply(conn, SOCKS_REP_ATYP_NOTSUP)
            return
        addr = _socks_atyp_addr(conn, atyp)
        port_bytes = _socks_read_exact(conn, 2)
        # -- the relayer behind the private port must be OUR tunnel
        reason = _socks_gate_check_owner(priv_port, tunnel_pid)
        if reason:
            _socks_reply(conn, SOCKS_REP_GENERAL)
            audit_log("verbose", f"socks gate: {peer}: {reason}")
            return
        # -- anonymous SOCKS5 client of `ssh -D`, target bytes verbatim
        try:
            up, rep = _socks_upstream_request(priv_port, atyp, addr,
                                              port_bytes)
        except socket.timeout:
            _socks_reply(conn, SOCKS_REP_HOST_UNREACH)
            return
        except ConnectionRefusedError:
            _socks_reply(conn, SOCKS_REP_REFUSED)
            return
        except OSError:
            # upstream framing garbage or any other dial failure: still a
            # well-formed refusal before the disconnect
            _socks_reply(conn, SOCKS_REP_GENERAL)
            return
        if rep != SOCKS_REP_OK:
            _socks_reply(conn, rep)
            return
        conn.settimeout(None)      # relaying may idle; EOF is the terminator
        up.settimeout(None)
        _socks_reply(conn, SOCKS_REP_OK)
        _socks_relay(conn, up)
    except (ConnectionError, OSError) as e:
        audit_log("verbose", f"socks gate: dropped {peer}: {e}")
    finally:
        if up is not None:
            up.close()
        _socks_drain_close(conn)


def socks_gate_serve(pub_port: int, priv_port: int, user: str,
                     password: str, tunnel_pid: int | None) -> socket.socket:
    """Bind the public listener and start the gate's daemon accept thread.
    Returns the listener; closing it ends the accept loop (the finally belt
    does exactly that), and the daemon flag means no crash path can leave
    the gate serving behind the process. Binding here -- and keeping the
    socket -- also removes the public port's own close-rebind window:
    fz_pick_port's TOCTOU comment now applies to the PRIVATE port only,
    where _socks_gate_check_owner guards it."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", pub_port))
    listener.listen(16)

    def accept_loop() -> None:
        while True:
            try:
                conn, _addr = listener.accept()
            except OSError:
                return     # listener closed: teardown (or process exit)
            threading.Thread(target=_socks_gate_conn,
                             args=(conn, priv_port, user, password,
                                   tunnel_pid),
                             daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True,
                     name=f"socks-gate:{pub_port}").start()
    return listener


def fz_socks_tunnel_plan(plan: dict) -> tuple[dict, str]:
    """The --tunnel session's rendered plan. FileZilla's SOCKS requests
    must dial target:port from the same vantage the -J chain's stdio
    forward dials from -- the LAST HOP (being able to reach the target is
    what makes it a jump). The -L design dialed 127.0.0.1 from the TARGET,
    which only works when the target's sshd listens on its own loopback;
    dropping the target block from the plan makes the last hop the tunnel
    session's destination instead (render_config wires ProxyCommand
    positionally, so the remaining blocks chain exactly as before, and the
    askpass map / host-key precheck cover the hops the tunnel really
    authenticates to). With no hops at all the target block stays the
    destination and dials originate from the target itself -- the site then
    keeps a loopback address. Returns (tunnel_plan, destination_block)."""
    blocks = [b for b in plan["blocks"] if b["block"] != BLOCK_TARGET]
    if not blocks:
        return plan, BLOCK_TARGET
    keys: list[str] = []
    for b in blocks:
        for i in b["identities"]:
            if i["kind"] == "keyref" and i["key"] not in keys:
                keys.append(i["key"])
    return {**plan, "blocks": blocks, "keys": keys}, \
        blocks[-1]["block"]


def fz_forward_spec(local_port: int, f: dict) -> str:
    """-L spec for the tunnel: the remote endpoint is resolved from the
    TARGET's namespace, so the remote port is the target's own sshd port
    from the book (22 when unset) -- NOT a hardcoded 22."""
    return f"{local_port}:127.0.0.1:{f['port'] or 22}"


def fz_pick_port() -> int:
    """A random free high port: bind-probed and closed again for ssh to
    bind. The tiny close-rebind TOCTOU window is covered by ssh's own bind
    failure being loud (the tunnel process exits non-zero)."""
    for _ in range(20):
        port = 49152 + secrets.randbelow(65535 - 49152 + 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            s.close()
    die("no free high port found in 49152-65535 after 20 tries")


def _ssh_blob(data: bytes) -> bytes:
    """SSH wire-format string: 4-byte big-endian length + raw bytes."""
    return len(data).to_bytes(4, "big") + data


def _ssh_mpint(value: int) -> bytes:
    """SSH-2 mpint the way PuTTY's put_mp_ssh2 writes it (crypto/mpint.c):
    minimal big-endian magnitude, one extra leading 0x00 when the top bit
    is set (values are unsigned), zero is a single 0x00 byte."""
    return _ssh_blob(
        value.to_bytes((value.bit_length() + 8) // 8, "big"))


def _ppk_key_blobs(key) -> tuple[str, bytes, bytes]:
    """(ssh_id, public blob, private blob) for a parsed cryptography key,
    byte-compatible with PuTTY's per-algorithm public_blob/private_blob
    writers: ssh-rsa (crypto/rsa.c rsa2_private_blob: d, p, q, iqmp --
    iqmp is q^-1 mod p, the same CRT convention cryptography uses),
    ssh-ed25519 (crypto/ecc-ssh.c: raw 32-byte compressed point as the
    public blob, fixed-length little-endian seed as the private blob),
    ECDSA nistp256/384/521 and ssh-dss (mpint encodings)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import (
        dsa, ec, ed25519, rsa)
    if isinstance(key, rsa.RSAPrivateKey):
        n = key.private_numbers()
        pub = (_ssh_blob(b"ssh-rsa") + _ssh_mpint(n.public_numbers.e)
               + _ssh_mpint(n.public_numbers.n))
        priv = (_ssh_mpint(n.d) + _ssh_mpint(n.p) + _ssh_mpint(n.q)
                + _ssh_mpint(n.iqmp))
        return "ssh-rsa", pub, priv
    if isinstance(key, ed25519.Ed25519PrivateKey):
        pub_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        seed = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        return ("ssh-ed25519",
                _ssh_blob(b"ssh-ed25519") + _ssh_blob(pub_raw),
                _ssh_blob(seed))
    if isinstance(key, ec.EllipticCurvePrivateKey):
        for curve_cls, name, field_bytes in (
                (ec.SECP256R1, "nistp256", 32),
                (ec.SECP384R1, "nistp384", 48),
                (ec.SECP521R1, "nistp521", 66)):
            if isinstance(key.curve, curve_cls):
                ssh_id = f"ecdsa-sha2-{name}"
                n = key.private_numbers()
                point = (b"\x04"
                         + n.public_numbers.x.to_bytes(field_bytes, "big")
                         + n.public_numbers.y.to_bytes(field_bytes, "big"))
                pub = (_ssh_blob(ssh_id.encode("ascii"))
                       + _ssh_blob(name.encode("ascii"))
                       + _ssh_blob(point))
                return ssh_id, pub, _ssh_mpint(n.private_value)
        die("unsupported EC curve for the FileZilla key export; supported: "
            "NIST P-256/P-384/P-521")
    if isinstance(key, dsa.DSAPrivateKey):
        pn = key.parameters().parameter_numbers()
        n = key.private_numbers()
        pub = (_ssh_blob(b"ssh-dss") + _ssh_mpint(pn.p) + _ssh_mpint(pn.q)
               + _ssh_mpint(pn.g) + _ssh_mpint(n.public_numbers.y))
        return "ssh-dss", pub, _ssh_mpint(n.x)
    die("unsupported key type for the FileZilla key export (PPK); "
        "supported: RSA, Ed25519, ECDSA (NIST P-256/384/521), DSA")


def _ppk_v2_kdf(passphrase: bytes) -> tuple[bytes, bytes]:
    """(AES-256-CBC key, HMAC-SHA-1 key) per sshpubk.c
    ssh2_ppk_derive_keys, fmt_version 2: counter-mode SHA-1 iteration for
    the cipher key (this format version always uses an all-zero CBC IV),
    a separate plain SHA-1 for the MAC key."""
    digest = b""
    ctr = 0
    while len(digest) < 32:
        digest += hashlib.sha1(ctr.to_bytes(4, "big") + passphrase).digest()
        ctr += 1
    mac_key = hashlib.sha1(
        b"putty-private-key-file-mac-key" + passphrase).digest()
    return digest[:32], mac_key


def _build_ppk_v2(key, passphrase: str, comment: str) -> bytes:
    """Serialize a parsed private key as an encrypted PuTTY PPK v2 file,
    byte-compatible with ppk_save_sb(fmt_version=2) (sshpubk.c) --
    verified against the testPPKLoadSave vectors in PuTTY's cryptsuite.
    The private blob is padded to the AES block with the leading bytes of
    its SHA-1 (PuTTY's scheme, not PKCS#7), MACed as padded plaintext,
    then AES-256-CBC encrypted under a zero IV."""
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    ssh_id, pub_blob, priv_blob = _ppk_key_blobs(key)
    cipher_name = "aes256-cbc"
    pad = -len(priv_blob) % 16
    padded = priv_blob + hashlib.sha1(priv_blob).digest()[:pad]
    cipher_key, mac_key = _ppk_v2_kdf(passphrase.encode("utf-8"))
    mac = hmac.new(
        mac_key,
        _ssh_blob(ssh_id.encode("ascii"))
        + _ssh_blob(cipher_name.encode("ascii"))
        + _ssh_blob(comment.encode("ascii"))
        + _ssh_blob(pub_blob) + _ssh_blob(padded),
        hashlib.sha1).hexdigest()
    enc = Cipher(algorithms.AES(cipher_key),
                 modes.CBC(b"\x00" * 16)).encryptor()
    priv_encrypted = enc.update(padded) + enc.finalize()

    def b64_block(data: bytes) -> tuple[str, int]:
        text = base64.b64encode(data).decode("ascii")
        return text, (len(text) + 63) // 64

    def wrap(text: str) -> str:
        return "\n".join(text[i:i + 64] for i in range(0, len(text), 64))

    pub_b64, pub_lines = b64_block(pub_blob)
    priv_b64, priv_lines = b64_block(priv_encrypted)
    file_bytes = (f"PuTTY-User-Key-File-2: {ssh_id}\n"
                  f"Encryption: {cipher_name}\n"
                  f"Comment: {comment}\n"
                  f"Public-Lines: {pub_lines}\n"
                  f"{wrap(pub_b64)}\n"
                  f"Private-Lines: {priv_lines}\n"
                  f"{wrap(priv_b64)}\n"
                  f"Private-MAC: {mac}\n").encode("ascii")
    _ppk_v2_selfcheck(file_bytes, passphrase)
    return file_bytes


def _ppk_v2_selfcheck(file_bytes: bytes, passphrase: str) -> None:
    """ppk_load parity check on our own output: re-parse the serialized
    file, decrypt the private blob and verify the MAC exactly the way the
    PuTTY loader does. Fail-closed: a serialization bug must die here, not
    surface as FileZilla's 'format not supported' dialog at connect time."""
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    headers: dict[str, str] = {}
    pub_parts: list[str] = []
    priv_parts: list[str] = []
    pub_left = priv_left = 0
    for line in file_bytes.decode("ascii").splitlines():
        if pub_left:
            pub_left -= 1
            pub_parts.append(line)
            continue
        if priv_left:
            priv_left -= 1
            priv_parts.append(line)
            continue
        name, _, value = line.partition(": ")
        headers[name] = value
        if name == "Public-Lines":
            pub_left = int(value)
        elif name == "Private-Lines":
            priv_left = int(value)

    def header(field: str) -> str:
        value = headers.get(field)
        if value is None:
            die(f"internal error: PPK v2 self-check: '{field}' missing")
        return value

    cipher_key, mac_key = _ppk_v2_kdf(passphrase.encode("utf-8"))
    priv_encrypted = base64.b64decode("".join(priv_parts))
    if len(priv_encrypted) % 16:
        die("internal error: PPK v2 self-check: private blob is not "
            "AES-block aligned")
    dec = Cipher(algorithms.AES(cipher_key),
                 modes.CBC(b"\x00" * 16)).decryptor()
    padded = dec.update(priv_encrypted) + dec.finalize()
    msg = (_ssh_blob(header("PuTTY-User-Key-File-2").encode("ascii"))
           + _ssh_blob(header("Encryption").encode("ascii"))
           + _ssh_blob(header("Comment").encode("ascii"))
           + _ssh_blob(base64.b64decode("".join(pub_parts)))
           + _ssh_blob(padded))
    if hmac.new(mac_key, msg, hashlib.sha1).hexdigest() \
            != header("Private-MAC"):
        die("internal error: PPK v2 self-check: MAC mismatch")


def ppk_export_bytes(container: bytes, old_pw: str | None, new_pw: str,
                     comment: str) -> bytes:
    """Vault key material (an OpenSSH/PEM container decrypted with old_pw
    in this process) -> PPK v2 file bytes re-encrypted under new_pw. Single
    seam so drills can fake the export without real key material."""
    key = _load_private_key(
        container, old_pw.encode("utf-8") if old_pw else None)
    return _build_ppk_v2(key, new_pw, comment)


def fz_export_key(container: bytes, old_pw: str, new_pw: str, rundir: Path,
                  name: str) -> tuple[Path, str]:
    """Vault key material -> a key file FileZilla can load natively,
    written into the session run dir. Format: encrypted PuTTY PPK v2
    (.ppk) -- the only private-key container FileZilla's SFTP engine loads
    without a 'Convert key file' prompt (verified on 3.69.5: OpenSSH/PEM
    containers are NOT auto-detected by fzsftp), and since the session key
    file and its random passphrase are fresh on every --tunnel run, that
    prompt would otherwise reappear at every connect. PPK v3 needs
    Argon2id, which the cryptography dependency does not provide; PPK v2
    is loadable by every PuTTY-derived engine. Returns (path, format)."""
    comment = (f"wtssh-fz-session-{name}" if name.isascii()
               else "wtssh-fz-session")
    try:
        file_bytes = ppk_export_bytes(container, old_pw, new_pw, comment)
    except Exception as e:
        # the class name keeps a missing-bcrypt UnsupportedAlgorithm from
        # masquerading as a corrupt key behind the re-import hint
        die(f"cannot convert the key material to PPK for FileZilla "
            f"({type(e).__name__}: {e}); re-import the key "
            f"('wtssh key remove ...' + 'wtssh key import ...')", 4)
    key_path = rundir / f"fz-{name}-key.ppk"
    secure_write(key_path, file_bytes)
    return key_path, "ppk2"


def fz_export_vault_session_key(name: str, keyname: str, blob_path: Path
                                ) -> tuple[tuple[str, str], str, Path]:
    """PIN-gated vault unwrap -> ephemeral encrypted PPK for one FileZilla
    launch. Shared by the --tunnel fallback path and the jump-free direct
    vault path (the merged SOCKS path uses pre-unlocked DEKs instead).
    Sweeps orphan run/key dirs first so a crash during a previous launch
    cannot leave session material stranded until some later tunnel/connect.
    Returns ((keyfile_path, source), passphrase, rundir). On any failure
    after the rundir is created, the rundir is wiped before the die
    propagates."""
    sweep_orphan_keydirs()
    sweep_orphan_rundirs()
    payload = vault_open_payload(
        KEY_AAD, keyname, blob_path.read_bytes(),
        f"key '{keyname}'",
        pin_text("pin_filezilla_export", name=name, key=keyname))
    container = payload.get("key")
    old_pw = payload.get("passphrase")
    if not isinstance(container, str) or not isinstance(old_pw, str):
        die(f"vault key '{keyname}' payload is missing its key "
            f"material; re-import it ('wtssh key remove {keyname}' "
            f"+ 'wtssh key import {keyname} <file>')", 4)
    if os.environ.get("WTSSH_NO_AGENT") != "1":
        # Unwrap-triggered auto-stage: this PIN also refreshes the 1h agent
        # cache so the next ssh connect skips the PIN. FileZilla itself
        # cannot use the agent (PPK flow); the benefit lands on connects.
        try:
            agent_stage_unlocked(
                {keyname: (base64.b64decode(container), old_pw)},
                source=f"filezilla {name}")
        except Exception as e:
            print(f"wtssh: warning: auto-agent skipped key '{keyname}': "
                  f"{e}", file=sys.stderr)
    passphrase = secrets.token_urlsafe(24)
    rundir = make_run_dir(RUN_DIR_PREFIX + "fz-")
    ok = False
    try:
        keyfile, kfmt = fz_export_key(base64.b64decode(container),
                                      old_pw, passphrase, rundir, name)
        session_keyfile = (str(keyfile), f"session-{kfmt}")
        ok = True
    finally:
        if not ok:
            # pre-main-try window: a failed export must not strand the
            # empty (or half-written) session dir
            secure_rmtree(rundir)
            rundir = None
            passphrase = None
            session_keyfile = None
    return session_keyfile, passphrase, rundir



def copy_to_clipboard(text: str) -> bool:
    """clip.exe via find_bin (System32 anchor; CWD excluded); token_urlsafe
    output is pure ASCII so stdin bytes need no codepage gymnastics."""
    try:
        clip = find_bin("clip")
        if clip is None:
            return False
        subprocess.run([clip], input=text.encode("ascii"), check=True,
                       capture_output=True, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def copy_text_to_clipboard(text: str) -> bool:
    """UTF-8-safe clipboard copy for long-lived secrets (login passwords).

    The password NEVER rides argv/env: pure-ASCII takes the clip.exe stdin
    path above; non-ASCII goes through a UTF-8 file inside a make_run_dir
    session dir (owner-only DACL + owner.pid, so the orphan sweeper reclaims
    it after a kill -- the file itself is secure_write owner-only, then
    overwrite-wiped with the dir) that powershell reads with Set-Clipboard
    (argv carries only the file path). Any failure is fail-closed (returns
    False) -- callers must never fall back to printing the secret."""
    try:
        text.encode("ascii")
        return copy_to_clipboard(text)
    except UnicodeEncodeError:
        pass
    ps_exe = find_bin("powershell")
    if ps_exe is None:
        return False
    try:
        rundir = make_run_dir(prefix=RUN_DIR_PREFIX + "clip-")
    except BaseException:
        return False
    tmp_path = rundir / "pw"
    try:
        try:
            secure_write(tmp_path, text.encode("utf-8"))
        except BaseException:
            return False
        ps = ("$p=$args[0]; "
              "$t=[IO.File]::ReadAllText($p,[Text.Encoding]::UTF8); "
              "Set-Clipboard -Value $t")
        try:
            r = subprocess.run([ps_exe, "-NoProfile", "-Command", ps,
                                str(tmp_path)],
                               capture_output=True, timeout=15)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    finally:
        ok, err = secure_wipe_tree(rundir)
        if not ok:
            print(f"wtssh: warning: could not wipe clipboard staging dir "
                  f"{rundir}: {err}", file=sys.stderr)


def fz_sync_server(server, f: dict, args, warnings: list, *,
                   endpoint: tuple[str, str] | None = None,
                   session_keyfile: tuple[str, str] | None = None,
                   proxy_pin: int | None = None
                   ) -> tuple[bool, dict]:
    """Merge one host-book entry into its wtssh-managed <Server>. The book is
    the source of truth for identity (host/port/user); auth follows the key
    the entry carries. A stored wtssh secret never travels -- password
    entries become ask-logontype sites that FileZilla prompts for itself.
    `endpoint` overrides the SITE endpoint only (...);
    `session_keyfile` is a key file generated for this very session.
    `proxy_pin` forces the per-site BypassProxy flag when a --tunnel run
    knows better than a stale hand-edit: 0 for a SOCKS session (the site
    MUST ride the generic proxy), 1 for the -L fallback (the site dials the
    local listener and must bypass any user-level generic proxy); None
    leaves the flag untouched (plain syncs). Returns (changed, auth-report)."""
    changed = False
    changed |= fz_set_child(server, "Host", endpoint[0] if endpoint
                            else f["host"])
    # Always write the port: ssh's default and FileZilla's SFTP default are
    # both 22, so an explicit value removes any reliance on how FileZilla
    # treats a missing <Port> element.
    changed |= fz_set_child(server, "Port",
                            endpoint[1] if endpoint else (f["port"] or 22))
    changed |= fz_set_child(server, "Protocol", 1)
    changed |= fz_set_child(server, "Type", 0)
    if proxy_pin is not None:
        # a stale per-site bypass flag must not silently opt a tunnel site
        # out of its proxy (SOCKS: a direct dial is unreachable in a
        # jump-only topology) nor send a fallback site's local-listener
        # dial through a user-level generic proxy
        changed |= fz_set_child(server, "BypassProxy", proxy_pin)
    if f["user"]:
        changed |= fz_set_child(server, "User", f["user"])
    else:
        el = server.find("User")
        if el is not None:
            server.remove(el)
            changed = True
        warnings.append("entry has no user; set one with "
                        "`wtssh edit NAME --user USER` before connecting")

    existing = (server.findtext("Keyfile") or "").strip()
    if RUN_DIR_PREFIX + "fz-" in existing:
        # A wiped session key file: not a binding worth keeping.
        existing = ""
        warnings.append("the site's keyfile pointed at a wiped session "
                        "key file; rebind a plaintext key with "
                        "`--keyfile` for direct use, or reopen the "
                        "SFTP entry so a fresh session key is exported")
    explicit = getattr(args, "keyfile", None)
    if session_keyfile:
        keyfile, source = session_keyfile
        if existing and source.startswith("session-"):
            # only an EXPORTED session key is ephemeral (wiped with the
            # FileZilla session); a book/override binding is stable,
            # nothing falls back after a plain sync
            warnings.append(f"this session replaces the site's existing "
                            f"keyfile binding ({existing}); a later plain "
                            f"sync falls back to ask/password unless you "
                            f"rebind with --keyfile")
    elif explicit:
        keyfile = str(Path(expand_key(explicit)))
        source = "override"
    elif f["key"] and not is_key_ref(f["key"]):
        keyfile = os.path.normpath(expand_key(f["key"]))
        source = "book"
    elif existing:
        keyfile, source = existing, "kept-existing"
        if f["key"] and is_key_ref(f["key"]):
            warnings.append("entry uses a TPM vault key (wtv:...), which "
                            "FileZilla cannot read; keeping the site's own "
                            "keyfile")
    else:
        keyfile, source = None, None
        if f["key"] and is_key_ref(f["key"]):
            warnings.append("entry uses a TPM vault key (wtv:...), which "
                            "FileZilla cannot read; the site falls back to "
                            "the password prompt -- bind a plaintext key "
                            "file once with "
                            "`wtssh filezilla NAME --keyfile PATH`")
        else:
            warnings.append("entry has no key; the site prompts for the "
                            "password (a stored wtssh secret is never "
                            "written into FileZilla's site list)")

    if keyfile:
        if not Path(keyfile).is_file():
            warnings.append(f"keyfile does not exist (yet): {keyfile}")
        changed |= fz_set_child(server, "Keyfile", keyfile)
        changed |= fz_set_child(server, "Logontype", FZ_LOGON_KEY)
        logon = "key"
    else:
        el = server.find("Keyfile")
        if el is not None:
            server.remove(el)
            changed = True
        changed |= fz_set_child(server, "Logontype", FZ_LOGON_ASK)
        logon = "ask"
    return changed, {"logontype": logon, "keyfile": keyfile,
                     "keyfileSource": source}


def resolve_tunnel_mode(tunnel_arg, jump: str | None) -> str:
    """`--tunnel` (yes, the historical flag) / `--tunnel auto` / absent ->
    "tunnel" | "direct". "auto" tunnels only when the entry carries a jump:
    this is the `sftp:<name>` menu entry's mode, so adding or removing the
    entry's `--jump` later needs no companion rewrite. A jump-free vault
    entry still exports a temporary session key on the direct path (PIN +
    ephemeral PPK); only the SOCKS/proxy half is jump-gated."""
    if not tunnel_arg:
        return "direct"
    if tunnel_arg == "auto":
        return "tunnel" if jump else "direct"
    return "tunnel"


def action_filezilla(args):
    """Sync a host-book entry into FileZilla's Site Manager -- inside a
    folder named after the current group, never touching the user's own
    sites -- and connect it with `filezilla -c <0/group/name>`. settings.json
    is only read here; sitemanager.xml is always written (rolling
    .wtssh.bak), and --tunnel additionally repoints filezilla.xml's generic
    proxy at the session's authenticated SOCKS gate (per-session
    credentials, so other local users cannot ride the tunnel anonymously;
    previous values restored once the launched FileZilla instance exits)."""
    if os.environ.get("WTSSH_FZ_SITEMANAGER"):
        print("wtssh: note: WTSSH_FZ_SITEMANAGER is set (drill mode); this "
              "run describes a copy, not the real FileZilla site list",
              file=sys.stderr)
    if os.environ.get("WTSSH_FZ_FILEZILLAXML"):
        print("wtssh: note: WTSSH_FZ_FILEZILLAXML is set (drill mode); "
              "generic-proxy writes describe a copy, not the real "
              "filezilla.xml", file=sys.stderr)
    data = load()
    p = require_profile(data, args.name)
    name = p["name"][len(PREFIX):]
    f = cmd_fields(p)
    if not f["host"]:
        die(f"entry '{name}' has no host; `wtssh edit {name} --host ...` "
            "first")
    warnings: list[str] = []
    tunneling = resolve_tunnel_mode(getattr(args, "tunnel", False), f["jump"])
    to_clipboard = bool(getattr(args, "to_clipboard", False))
    if to_clipboard:
        # Explicit opt-in only: the long-lived login password leaves the
        # vault for the clipboard (not a secret channel). Validate BEFORE
        # any PIN gesture or site write; the native Yes/No below is the
        # displayed secondary confirmation.
        if getattr(args, "no_open", False):
            die("--to-clipboard needs a launch; drop --no-open")
        if getattr(args, "remove_site", False):
            die("--to-clipboard cannot be combined with --remove-site")
        if getattr(args, "keyfile", None):
            die("--to-clipboard cannot be combined with --keyfile "
                "(key auth needs no login password)")
        if tunneling == "tunnel":
            die("--to-clipboard is direct-only; entry "
                f"'{name}' resolves to a tunnel -- use key auth or a "
                "direct entry")
        if f["key"] and is_key_ref(f["key"]):
            die(f"entry '{name}' uses a vault key (wtv:...): it has no "
                f"stored login password -- its session passphrase already "
                f"goes to the clipboard automatically on launch")
        elif f["key"]:
            die(f"entry '{name}' binds a key file: its site is key-type "
                f"(Logontype 5) with nowhere to paste a login password -- "
                f"drop --to-clipboard, or unbind first "
                f"(`wtssh edit {name} --key none`)")
        if not secret_path(name).exists():
            die(f"entry '{name}' has no stored passphrase "
                f"(`wtssh secret set {name}` first, or type it in "
                f"FileZilla's own password prompt)")
        if not confirm_password_to_clipboard(name, entry_dest_label(p)):
            die("password-to-clipboard confirmation declined; "
                "FileZilla not launched", 2)
    if f["jump"] and tunneling != "tunnel":
        warnings.append(f"FileZilla SFTP cannot express a jump chain; the "
                        f"book jump '{f['jump']}' is ignored (direct "
                        "connection)")
    port = None        # the tunnel's PRIVATE listener (ssh -D / -L binds it)
    pub_port = None    # the PUBLIC listener (the socks gate); merged path only
    gate_user = None   # per-session RFC 1929 credentials for the gate
    gate_password = None
    gate_sock = None   # the gate's listening socket; finally belt closes it
    forward_spec = None
    tunnel_mode = None  # socks-last-hop / socks-target / forward-fallback
    rundir = None
    passphrase = None
    session_keyfile = None
    endpoint = None  # site-endpoint override; --tunnel only, see below
    chain = None     # merged single-PIN tunnel: plan + destination + run
    keydirs: list[Path] = []
    tunnel_proc = None
    fz_proc = None       # the FileZilla instance THIS run launched
    proxy_saved = None   # generic-proxy state captured before the launch
    session_closed = False  # the tail's own cleanup ran (fz + proxy done)
    rundir_clean = False
    keydirs_clean = True  # only the merged path populates ssh-side containers
    if tunneling == "tunnel":
        # the mode exclusions fire only when auto actually resolved to a
        # tunnel: `--tunnel auto --no-open` on a jump-free entry is a legal
        # sync-only run, and --keyfile binds normally there
        # (getattr: only --to-clipboard is documented as optional on old
        # test namespaces; tunnel/keyfile/remove_site/no_open always come
        # from the parser, but getattr keeps direct action_filezilla callers
        # from tripping on AttributeError either way)
        if getattr(args, "keyfile", None):
            die("--tunnel generates the FileZilla key itself; --keyfile "
                "conflicts with it")
        if getattr(args, "remove_site", False):
            die("--tunnel cannot be combined with --remove-site")
        if getattr(args, "no_open", False):
            die("--tunnel opens FileZilla by definition; drop --no-open")
        port = fz_pick_port()
        keyname = None
        if f["key"] and is_key_ref(f["key"]):
            ref = resolve_key_ref(f["key"])
            blob_path, keyname = ref
            if not blob_path.exists():
                die(f"vault key '{keyname}' does not exist ('wtssh key "
                    f"list' shows them)", 4)
        # Plan BEFORE any gesture: build_render_plan's one deliberate
        # die (a stored-secret hop under active dispatch) must surface
        # before a PIN is spent, not after. The tunnel is a -D SOCKS
        # listener; dials originate at the session's endpoint, so the
        # plan is truncated to the LAST HOP -- the same vantage the -J
        # chain's stdio forward dials from.
        targv = ssh_argv(p)
        at = option_region_start(targv)
        # The entry's -p names the TARGET's port; the tunnel's destination
        # is the LAST HOP, whose port lives in its own config block -- a
        # surviving -p would override that block (command line beats
        # config) and misdial the hop. Stripped on the SOCKS path only
        # (the fallback child's destination IS the target block, where the
        # stored -p stays consistent), and only inside the OPTION region
        # (argv_option_slots stops at the destination / `--`, so a remote
        # command's own `-p` survives).
        _start, slots = argv_option_slots(targv)
        for idx, width in reversed(slots):
            if targv[idx] == "-p":
                del targv[idx:idx + width]
        # Pin the PRIVATE listener to loopback: an entry-level
        # `GatewayPorts yes` would otherwise rebind it to a wildcard
        # address (anonymous reach from other hosts, and the gate's
        # ownership check only recognizes 127.0.0.1 rows).
        targv[at:at] = ["-N", "-D", f"127.0.0.1:{port}"]
        plan, reason = build_render_plan(data, p, f, targv,
                                         dispatch_active=True)
        if plan is not None:
            # Merged single-PIN path: exporting the FileZilla session
            # key (vault entries) and unlocking every chain key share
            # ONE unwrap-many gesture (all blobs wrap to the same TPM
            # vault key, and PCP does not re-prompt within a key
            # handle). What the third-party app receives is unchanged --
            # fresh random session material, wiped with the tunnel.
            tplan, dest_block = fz_socks_tunnel_plan(plan)
            # The site must name the address FileZilla dials THROUGH the
            # proxy: the entry's real host:port (resolved at the last
            # hop). Without hops the endpoint is the target itself, so
            # the site keeps a loopback address (the sshd-side dial is
            # local to it either way).
            endpoint = (None if dest_block != BLOCK_TARGET
                        else ("127.0.0.1", str(port)))
            tunnel_mode = ("socks-last-hop" if dest_block != BLOCK_TARGET
                           else "socks-target")
            # Gate material BEFORE any PIN gesture: a missing free port dies
            # cheaply. `port` stays the PRIVATE listener (ssh binds it only
            # after the chain authenticates); FileZilla only ever sees
            # pub_port.
            pub_port = fz_pick_port()
            gate_user = secrets.token_urlsafe(16)
            gate_password = secrets.token_urlsafe(16)
            sweep_orphan_keydirs()
            sweep_orphan_rundirs()
            unlocked = _chain_unlock_keys(
                tplan["keys"], name, entry_dest_label(p),
                extra_keys=((keyname,) if keyname else ()),
                ctx_msgid="pin_tunnel_batch")
            if os.environ.get("WTSSH_NO_AGENT") != "1":
                # Same unwrap-triggered auto-stage as connects: this PIN
                # refreshes the 1h agent cache for the next ssh connect.
                try:
                    agent_stage_unlocked(unlocked,
                                         source=f"filezilla-tunnel {name}")
                except Exception as e:
                    print(f"wtssh: warning: auto-agent skipped: {e}",
                          file=sys.stderr)
            rundir = make_run_dir(RUN_DIR_PREFIX + "fz-")
            ok = False
            try:
                if keyname:
                    keydata, old_pw = unlocked[keyname]
                    passphrase = secrets.token_urlsafe(24)
                    keyfile, kfmt = fz_export_key(keydata, old_pw,
                                                  passphrase, rundir, name)
                    session_keyfile = (str(keyfile), f"session-{kfmt}")
                chain = {"plan": tplan, "argv": targv, "dest": dest_block,
                         "run": _chain_materialize_run(
                             tplan, targv, rundir, unlocked, False)}
                ok = True
            finally:
                if not ok:
                    # this window sits BEFORE the function's main
                    # try/finally: a die here (host-key probe refusal
                    # inside _chain_materialize_run, a failed export)
                    # must not strand the askpass map, the config or
                    # the exported session key -- the decrypted
                    # containers self-clean inside the helper
                    secure_rmtree(rundir)
                    rundir = None
                    passphrase = None
                    session_keyfile = None
            keydirs = chain["run"]["keydirs"]
            keydirs_clean = False
        else:
            # Fallback (the chain keeps the -J path): today's shape --
            # the parent exports the session key on its own gesture, the
            # child connect unwraps the chain on its own. The child runs
            # --tunnel-forward (-L): dials originate at the target, so
            # the site stays endpoint-rewritten to 127.0.0.1 and the
            # generic proxy is not involved.
            endpoint = ("127.0.0.1", str(port))
            tunnel_mode = "forward-fallback"
            forward_spec = fz_forward_spec(port, f)
            if reason:
                print(f"wtssh: note: tunnel keeps the child-connect "
                      f"path: {reason}", file=sys.stderr)
            if keyname:
                session_keyfile, passphrase, rundir = (
                    fz_export_vault_session_key(name, keyname, blob_path))
        if not keyname and f["key"]:
            # a plaintext book key needs no export: FileZilla reads it
            # directly, on either tunnel path
            session_keyfile = (os.path.normpath(expand_key(f["key"])), "book")
    elif (f["key"] and is_key_ref(f["key"])
          and not getattr(args, "keyfile", None)
          and not getattr(args, "remove_site", False)
          and not getattr(args, "no_open", False)):
        # Jump-free vault entry: FileZilla still cannot read wtv:, so export
        # an ephemeral encrypted PPK for THIS launch (same material as the
        # --tunnel session key, without a SOCKS proxy). Sync-only runs
        # (--no-open) stay on the ask/password fallback -- a session key
        # with nothing to hand it to would be wiped immediately.
        blob_path, keyname = resolve_key_ref(f["key"])
        if not blob_path.exists():
            die(f"vault key '{keyname}' does not exist ('wtssh key "
                f"list' shows them)", 4)
        session_keyfile, passphrase, rundir = (
            fz_export_vault_session_key(name, keyname, blob_path))
    try:
        site_file = fz_site_file()
        with Lock(fz_lock_path()):
            tree = fz_load_tree(site_file)
            servers = tree.getroot().find("Servers")
            changed = False
            if getattr(args, "remove_site", False):
                folder = fz_find_folder(servers, GROUP)
                server = (fz_find_server(folder, name)
                          if folder is not None else None)
                if server is None:
                    die(f"no wtssh-managed FileZilla site '{GROUP}/{name}' "
                        f"in {site_file}")
                folder.remove(server)
                if len(folder) == 0:  # an emptied group folder holds no data
                    servers.remove(folder)
                changed = True
                auth = {"logontype": None, "keyfile": None,
                        "keyfileSource": None}
            else:
                # Everything the book knows, including hidden jump
                # identities: decides which folder members count as
                # "not ours" below.
                book_names = {q["name"][len(PREFIX):]
                              for q in data["profiles"]["list"]}
                folder = fz_find_folder(servers, GROUP)
                if folder is None:
                    folder = ET.Element("Folder")
                    # Mixed content is fine for pugixml (FileZilla reads the
                    # folder name as the trimmed text before the first
                    # child); FileZilla re-indents the file on its next own
                    # save.
                    folder.text = GROUP
                    servers.append(folder)
                    changed = True
                server = fz_find_server(folder, name)
                if server is None:
                    # Warn only about sites the book cannot account for:
                    # our own previously synced sites are managed, not
                    # "of its own".
                    owned = sum(1 for c in folder
                                if c.tag == "Server"
                                and fz_element_name(c) not in book_names)
                    if owned:
                        warnings.append(
                            f"adopting the existing FileZilla folder "
                            f"'{GROUP}' which already holds {owned} site(s) "
                            f"outside the host book; '--remove-site' removes "
                            f"by name and could hit those")
                    server = fz_new_server(name)
                    folder.append(server)
                    changed = True
                server_changed, auth = fz_sync_server(
                    server, f, args, warnings,
                    endpoint=endpoint, session_keyfile=session_keyfile,
                    proxy_pin=(0 if chain is not None else 1)
                    if tunneling == "tunnel" else None)
                changed |= server_changed
                # rename/remove/`--group` switches do not propagate here:
                # sites that match no host-book entry any more are flagged,
                # not touched
                orphans = sorted(
                    fz_element_name(c) for c in folder
                    if c.tag == "Server"
                    and fz_element_name(c) not in book_names)
                if orphans:
                    warnings.append(
                        f"site(s) in the FileZilla folder '{GROUP}' match "
                        f"no host-book entry any more (rename/remove do not "
                        f"propagate; clean up with `wtssh filezilla NAME "
                        f"--remove-site`): " + ", ".join(orphans))
            if changed:
                fz_save_tree(tree, site_file)

        site_path = "0/" + "/".join(fz_escape_segment(s)
                                    for s in (GROUP, name))
        launched = False
        password_clipboard = False
        if not getattr(args, "remove_site", False) \
                and not getattr(args, "no_open", False):
            if to_clipboard:
                # Second gesture after the Yes/No above: TPM PIN unwrap,
                # then clipboard only. The password is NEVER printed to
                # stdout/stderr/JSON/logs; copy failure still launches
                # (the ask-type site lets the user type manually).
                # Order note: the site sync above already ran, so a PIN
                # cancel here leaves a synced-but-unlaunched ask site --
                # harmless (no secrets, idempotent) and documented in
                # SKILL.md; the PIN stays adjacent to the use point so the
                # password lives in memory for the shortest window.
                ctx = pin_text("pin_filezilla_password", name=name,
                               dest=entry_dest_label(p))
                login_pw = secret_load(name, ctx)
                if not login_pw:
                    die(f"stored passphrase for '{name}' could not be "
                        f"unlocked; FileZilla not launched", 4)
                try:
                    password_clipboard = copy_text_to_clipboard(login_pw)
                finally:
                    # Drop the reference only (Python strs are immutable;
                    # no secure-zero cargo-cult) -- the clipboard staging
                    # file above is what gets overwrite-wiped.
                    login_pw = None
                if password_clipboard:
                    print("wtssh: note: login password copied to the "
                          "clipboard (not printed); paste it into "
                          "FileZilla's password prompt, then overwrite the "
                          "clipboard -- do not tick 'Remember password'",
                          file=sys.stderr)
                else:
                    warnings.append("login password could not be copied to "
                                    "the clipboard; type it in FileZilla's "
                                    "own password prompt (it was never "
                                    "printed)")
                    print("wtssh: warning: clipboard copy failed; type the "
                          "login password in FileZilla's own password "
                          "prompt (it is never printed by wtssh)",
                          file=sys.stderr)
            exe = filezilla_exe(args)
            if tunneling == "tunnel":
                if chain is not None:
                    # Merged single-PIN path: the parent launches the tunnel
                    # ssh itself -- the export and the chain unlock already
                    # shared one gesture, so the child-connect detour (its
                    # own PIN) is gone.
                    tun_argv = _chain_launch_argv(chain["plan"],
                                                  chain["argv"], chain["run"],
                                                  chain["dest"])
                    if chain["run"]["dispatch"]:
                        env = dispatch_env(chain["run"]["map_path"])
                    else:
                        env = dict(os.environ)
                    audit_log("verbose", f"rendered chain for {name!r}: "
                               f"{len(chain['plan']['blocks'])} block(s), "
                               f"{len(chain['plan']['keys'])} vault key(s)")
                    try:
                        tunnel_proc = subprocess.Popen(tun_argv, env=env)
                    except OSError as e:
                        die(f"cannot start the tunnel process: {e}")
                    # Front the anonymous `ssh -D` with the authenticated
                    # gate. The gate's own bind failure is loud (die, and
                    # the finally belt reaps tunnel_proc): unlike ssh, the
                    # gate keeps its socket, so the public port has no
                    # close-rebind window at all.
                    try:
                        gate_sock = socks_gate_serve(pub_port, port,
                                                     gate_user, gate_password,
                                                     tunnel_proc.pid)
                    except OSError as e:
                        die(f"cannot bind the SOCKS gate listener on "
                            f"127.0.0.1:{pub_port}: {e}")
                else:
                    # Fallback: the tunnel subprocess is a full connect
                    # (legacy -J path or plain-key entry; vault unwrap,
                    # dispatcher, host-key probe included) in pure-forward
                    # mode. env: the child must drill where the parent
                    # drills (--settings/--secrets/--keys) and must never
                    # silently dry-run on a stale WTSSH_RENDER_DRY.
                    env = os.environ.copy()
                    env.pop("WTSSH_RENDER_DRY", None)
                    env["WTSSH_SETTINGS"] = str(settings_path())
                    if getattr(args, "secrets", None):
                        env["WTSSH_SECRETS"] = str(SECRETS_DIR)
                    if getattr(args, "keys", None):
                        env["WTSSH_KEYS"] = str(KEYS_DIR)
                    try:
                        tunnel_proc = subprocess.Popen(
                            [sys.executable, str(SCRIPTS / "wtssh.py"),
                             "connect", name, "--tunnel-forward",
                             forward_spec], env=env)
                    except OSError as e:
                        die(f"cannot start the tunnel process: {e}")
                # Wait for the local listener so FileZilla's first attempt
                # can actually proxy. OpenSSH binds local -D listeners only
                # AFTER the chain authenticates, so this budget covers the
                # full connect (kex + auth over every hop), and the poll
                # check below catches a tunnel that dies before binding
                # (refused hop, bad key). Any PIN was already taken above.
                # The probe targets the PRIVATE listener (`port`) on the
                # merged path -- the gate's public port binds instantly and
                # would say nothing about the chain; on the fallback the -L
                # listener IS `port`, so one probe serves both.
                deadline = time.time() + 60
                listener_up = False
                while time.time() < deadline:
                    if tunnel_proc.poll() is not None:
                        rc = tunnel_proc.returncode
                        die(f"the tunnel process exited early with code "
                            f"{rc}; see its output above")
                    probe = socket.socket()
                    try:
                        if probe.connect_ex(("127.0.0.1", port)) == 0:
                            listener_up = True
                            break
                    finally:
                        probe.close()
                    time.sleep(0.2)
                if not listener_up:
                    # still authenticating (slow hops, dialogs) -- go on,
                    # but say why FileZilla's first attempts may fail
                    print("wtssh: note: the tunnel listener did not come "
                          "up within 60s (the chain may still be "
                          "authenticating); launching FileZilla anyway -- "
                          "reconnect inside FileZilla once the tunnel is "
                          "up", file=sys.stderr)
                # Repoint FileZilla's generic proxy at the SOCKS listener
                # (filezilla.xml is read once per launch); the captured
                # state is restored the moment OUR FileZilla instance
                # exits, which is also when the proxy process ends. The
                # fallback's -L path must NOT touch it: its site dials the
                # -L listener directly, and a proxy would rewrite the dial
                # a second time.
                if chain is not None:
                    proxy_saved = fz_proxy_apply(pub_port, gate_user,
                                                 gate_password)
                    print("wtssh: note: the tunnel's local SOCKS listener "
                          "now requires this session's credentials "
                          "(FileZilla has been configured with them); "
                          "unauthenticated local processes are refused",
                          file=sys.stderr)
            try:
                fz_proc = subprocess.Popen([exe, "-c", site_path])
                launched = True
            except OSError as e:
                if tunnel_proc is not None:
                    tunnel_proc.terminate()
                fz_proxy_restore(proxy_saved)
                die(f"cannot launch {exe}: {e}")
        clipboard = False
        tty = sys.stdout is not None and sys.stdout.isatty()
        if passphrase is not None:
            # stderr keeps stdout pure JSON; same terminal the user watches.
            clipboard = copy_to_clipboard(passphrase)
            if tty or not clipboard:
                # A real terminal: the human watching IS the reader, so the
                # passphrase may be shown. Piped stdout with a FAILED
                # clipboard is the one shape left with no delivery channel
                # at all -- fail open there, loudly, rather than strand the
                # session key behind a secret nobody can reach.
                how = ("copied to the clipboard" if clipboard
                       else "CLIPBOARD COPY FAILED")
                print(f"wtssh: note: FileZilla key passphrase ({how}; paste "
                      f"it into FileZilla's 'SSH key passphrase' dialog -- "
                      f"every FileZilla vault session generates a new one):",
                      file=sys.stderr)
                print(f"wtssh: note:     {passphrase}", file=sys.stderr)
            else:
                # Piped stdout (an agent transcript, a CI log capture): the
                # passphrase must not land in captured output. The clipboard
                # is the delivery channel; announce it without the secret.
                print(f"wtssh: note: FileZilla key passphrase copied to the "
                      f"clipboard (not printed: stdout is piped); paste it "
                      f"into FileZilla's 'SSH key passphrase' dialog -- "
                      f"every FileZilla vault session generates a new one",
                      file=sys.stderr)
        result = {
            "name": name,
            "site": site_path,
            "sitemanager": str(site_file),
            "changed": changed,
            "auth": auth,
            "warnings": warnings,
            "launched": launched,
        }
        if getattr(args, "tunnel", False) == "auto":
            # what the menu entry's mode resolved to on THIS click
            result["tunnelAuto"] = ("tunnel" if tunneling == "tunnel"
                                    else "direct")
        if tunneling == "tunnel":
            result["tunnel"] = {
                # socks-last-hop: dials originate at the last hop, the site
                # keeps the entry's real address. socks-target: no hops, the
                # site keeps a loopback address. forward-fallback: the child
                # connect's -L shape, site endpoint-rewritten to 127.0.0.1
                # and NO socks listener (proxy is null).
                "mode": tunnel_mode,
                # localPort is what the CLIENT dials: the gate's public port
                # on the merged path, the -L listener on the fallback. The
                # gate's user/password never ride the JSON (captured stdout
                # is a transcript); proxyAuth only says they exist.
                "localPort": port if chain is None else pub_port,
                "proxy": (f"socks5://127.0.0.1:{pub_port}"
                          if chain is not None else None),
                "proxyAuth": chain is not None,
                "siteEndpoint": {"host": (endpoint[0] if endpoint
                                          else f["host"]),
                                 "port": int((endpoint[1] if endpoint
                                              else f["port"]) or 22)},
                # merged path: ONE gesture iff anything was unwrapped
                # (chain vault keys and/or the export key); the fallback
                # pops a PIN only for its own export gesture
                "pinPrompts": (1 if chain is not None
                               and (chain["plan"]["keys"] or keyname)
                               else 1 if passphrase is not None else 0)}
        if passphrase is not None:
            # `passphrase` rides the JSON only toward a human terminal;
            # piped readers get `clipboard` plus the stderr notice
            # instead -- a secret must not land in captured stdout.
            # Covers both --tunnel and the jump-free direct vault export.
            if tty:
                result["passphrase"] = passphrase
            result["clipboard"] = clipboard
            if tunneling == "direct":
                result["sessionKey"] = {
                    "mode": "direct-vault",
                    "pinPrompts": 1,
                    "keyfileSource": (session_keyfile[1]
                                      if session_keyfile else None),
                }
        if to_clipboard:
            # Long-lived login password: NEVER rides the JSON -- only the
            # copy outcome does. `clipboard` above stays reserved for the
            # ephemeral session-key passphrase.
            result["passwordClipboard"] = password_clipboard
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if fz_proc is not None:
            # Keep this process alive for the FileZilla lifetime on BOTH
            # paths. The direct (`--tunnel auto` with no jump) path used to
            # return immediately after Popen; Windows Terminal then closes
            # the sftp: tab (closeOnExit=automatic) and its Job Object
            # KILL_ON_JOB_CLOSE reaps FileZilla with it -- the window
            # flashes and vanishes. Waiting here keeps the tab/job open
            # until the user closes FileZilla. The tunnel path additionally
            # tears the proxy down when FileZilla exits.
            fz_code = None
            interrupted = False
            tunnel_died_first = False
            try:
                while True:
                    try:
                        fz_code = fz_proc.wait(timeout=0.5)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if tunnel_proc is not None and tunnel_proc.poll() is not None:
                        # the proxy died first: the site can no longer
                        # connect, so close our FileZilla with it
                        tunnel_died_first = True
                        fz_proc.terminate()
                        fz_code = fz_proc.wait()
                        print("wtssh: note: the tunnel exited early; "
                              "FileZilla has been closed (its proxy "
                              "is gone)", file=sys.stderr)
                        break
            except KeyboardInterrupt:
                interrupted = True
                if tunnel_proc is not None:
                    tunnel_proc.terminate()
                    try:
                        tunnel_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel_proc.kill()
                # Close OUR FileZilla too: with the proxy dead the
                # window is stranded, and leaving it open would race
                # its exit-save against the restore below (its final
                # write would re-pin the dead SOCKS port globally)
                fz_proc.terminate()
                fz_code = fz_proc.wait()
                print("wtssh: note: Ctrl-C closed FileZilla"
                      + (" and the tunnel" if tunnel_proc is not None else ""),
                      file=sys.stderr)
            if tunnel_proc is not None:
                if tunnel_proc.poll() is None:
                    tunnel_proc.terminate()
                    try:
                        tunnel_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel_proc.kill()
                if rundir is not None:
                    secure_rmtree(rundir)  # wipes config, map and session key
                    rundir_clean = True
                wipe_session_dirs(keydirs)  # the ssh-side containers
                keydirs_clean = True
                # restore LAST and failure-contained (same discipline as the
                # finally belt): a die here must not strand the session
                # secrets wiped above
                try:
                    fz_proxy_restore(proxy_saved)
                except BaseException as e:
                    print(f"wtssh: warning: could not restore FileZilla's "
                          f"generic proxy ({e}); the .wtssh.bak beside "
                          f"FileZilla's filezilla.xml holds the pre-tunnel "
                          f"state", file=sys.stderr)
                session_closed = True
                if interrupted:
                    sys.exit(130)
                print(f"wtssh: note: FileZilla closed (exit {fz_code}); "
                      f"tunnel stopped (exit {tunnel_proc.poll()}); the "
                      f"session key file has been wiped and the generic "
                      f"proxy restored", file=sys.stderr)
                if fz_code is not None and tunnel_proc.poll() not in (None, 0) \
                        and tunnel_died_first:
                    # a proxy that died under the session is a failed session:
                    # report the tunnel's own exit code, not a clean 0
                    sys.exit(tunnel_proc.poll() or 1)
            elif rundir is not None:
                # jump-free vault export: no tunnel/proxy, but the ephemeral
                # PPK must still die with the FileZilla window
                secure_rmtree(rundir)
                rundir_clean = True
                session_closed = True
                if interrupted:
                    sys.exit(130)
                print(f"wtssh: note: FileZilla closed (exit {fz_code}); "
                      f"the session key file has been wiped",
                      file=sys.stderr)
            elif interrupted:
                sys.exit(130)
    finally:
        if gate_sock is not None:
            # ends the gate's accept thread (its handlers are daemons); on
            # the happy path the FileZilla session is already over
            gate_sock.close()
        if tunnel_proc is not None and tunnel_proc.poll() is None:
            # any die/exception after the tunnel was started
            tunnel_proc.terminate()
        if not session_closed:
            # any die/exception between the proxy apply and the tail's own
            # cleanup: close the FileZilla window this run opened (its
            # proxy is going away)
            if fz_proc is not None and fz_proc.poll() is None:
                fz_proc.terminate()
                try:
                    fz_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        if rundir is not None and not rundir_clean:
            # any die/exception between session-dir creation and the
            # happy-path cleanup above
            secure_rmtree(rundir)
        if not keydirs_clean:
            wipe_session_dirs(keydirs)
        if not session_closed:
            # LAST, and failure-contained: the restore itself can die
            # (filezilla.xml corrupt/unwritable at cleanup time) and must
            # never abort the secret wipes above -- the .wtssh.bak beside
            # FileZilla's filezilla.xml holds the pre-tunnel state for a
            # manual fix
            try:
                fz_proxy_restore(proxy_saved)
            except BaseException as e:
                print(f"wtssh: warning: could not restore FileZilla's "
                      f"generic proxy ({e}); the .wtssh.bak beside "
                      f"FileZilla's filezilla.xml holds the pre-tunnel "
                      f"state", file=sys.stderr)


# ------------------------------------------------------------------ secrets

def secret_blob_stem(name: str) -> str:
    """The sanitized blob stem for `name`. secret_path and the case-
    collision check must agree on this mapping, so it lives in one place."""
    return name.strip().replace("/", "_").replace("\\", "_") or "_"


def secret_path(name: str) -> Path:
    # sanitized so a name that never went through clean_name (an imported ssh
    # config alias, say) still maps to a legal file name instead of dying.
    return SECRETS_DIR / f"{secret_blob_stem(name)}.bin"


def secret_case_collision(name: str) -> str | None:
    """A differently-cased existing blob stem that NTFS maps onto the same
    file as `name`'s blob: identity comparison is case-sensitive, the
    filesystem is not, so storing would silently overwrite the other
    entry's secret (whose connect then dies on the payload name check).
    Returns the colliding stem, or None."""
    want = f"{secret_blob_stem(name)}.bin".lower()
    if SECRETS_DIR.exists():
        for p in SECRETS_DIR.glob("*.bin"):
            if p.name.lower() == want and p.name != f"{secret_blob_stem(name)}.bin":
                return p.stem
    return None


def dpapi(action: str, payload: str) -> str:
    """Run scripts/dpapi.ps1 with payload on stdin; returns stdout."""
    proc = subprocess.run(
        [resolve_bin("powershell"), "-NoProfile", "-ExecutionPolicy",
         "Bypass", "-File", str(SCRIPTS / "dpapi.ps1"), action],
        input=payload, capture_output=True, text=True, encoding="utf-8",
    )
    if proc.returncode != 0:
        die(f"dpapi {action} failed: {(proc.stderr or 'unknown').strip()}")
    return proc.stdout


# ------------------------------------------------------------------ vault

VAULT_KEY = os.environ.get("WTSSH_VAULT_KEY", "wtssh-vault")


def vault_run(action: str, payload: str | None = None,
              use_context: str | None = None) -> subprocess.CompletedProcess:
    """Run scripts/cng-vault.ps1 (NCrypt host). Payload travels on stdin,
    never argv (same-user processes can read foreign command lines).
    `use_context` is NOT a secret (host/key names) and is passed as
    -UseContext so the CNG PIN dialog can show why the PIN is needed.
    Exit codes: 0 ok, 2 vault key missing, 3 consent refused/cancelled,
    4 provider unavailable, 1 other."""
    cmd = [resolve_bin("powershell"), "-NoProfile", "-ExecutionPolicy",
           "Bypass", "-File", str(SCRIPTS / "cng-vault.ps1"), action,
           "-KeyName", VAULT_KEY]
    if use_context:
        cmd += ["-UseContext", use_context]
    return subprocess.run(
        cmd, input=payload, capture_output=True, text=True, encoding="utf-8",
    )


def vault_exists() -> bool:
    proc = vault_run("status")
    if proc.returncode == 4:
        die("TPM crypto provider unavailable on this machine; "
            "the wtssh vault requires a TPM (Platform Crypto Provider)", 4)
    if proc.returncode != 0:
        die(f"vault status failed: {(proc.stderr or 'unknown').strip()}")
    try:
        return json.loads(proc.stdout)["exists"] is True
    except (ValueError, KeyError):
        die(f"vault status returned unparseable output: {proc.stdout!r}")


def vault_wrap(dek: bytes) -> bytes:
    """Silent (public-key op, no gesture): RSA-OAEP(SHA256) the DEK."""
    proc = vault_run("wrap", dek.hex())
    if proc.returncode == 2:
        die("vault key not initialized; run 'wtssh vault init' first", 4)
    if proc.returncode != 0:
        die(f"vault wrap failed: {(proc.stderr or 'unknown').strip()}")
    return bytes.fromhex(proc.stdout.strip())


def pin_context(text: str) -> str:
    """Sanitize a CNG Use Context string: no controls, no leading dash
    (would look like a powershell switch), capped so the PIN UI can show it."""
    cleaned = "".join(c if ord(c) >= 32 and c != "\x7f" else " " for c in text)
    cleaned = " ".join(cleaned.split())
    if cleaned.startswith("-"):
        cleaned = " " + cleaned
    return cleaned[:180]


def pin_text(msgid: str, **kwargs) -> str:
    """Localized PIN-purpose string (dialog + stderr). Missing kwargs must
    not silently produce a blank context -- vault_unwrap refuses those."""
    tmpl = ui_texts()[msgid]
    return pin_context(tmpl.format(**kwargs))


def entry_dest_label(p: dict) -> str:
    """user@host[:port] for PIN copy; falls back to the entry name."""
    name = p["name"][len(PREFIX):]
    f = cmd_fields(p)
    host = f.get("host") or name
    dest = f"{f['user']}@{host}" if f.get("user") else host
    if f.get("port"):
        dest += f":{f['port']}"
    return dest


def vault_unwrap(wrapped: bytes, use_context: str) -> bytes:
    """Interactive: pops the CNG consent dialog (TPM PIN). `use_context`
    is required -- an unexplained PIN dialog is a footgun."""
    return vault_unwrap_many([wrapped], use_context)[0]


def vault_unwrap_many(wrapped: list[bytes], use_context: str) -> list[bytes]:
    """Interactive: ONE CNG consent dialog (TPM PIN) for the whole batch.
    PCP does not re-prompt within the same key handle, so a whole jump
    chain unwraps with a single gesture. `use_context` is required -- an
    unexplained PIN dialog is a footgun. Batch aborts fail-closed: any
    mid-batch decrypt error returns nothing."""
    ctx = pin_context(use_context)
    if not ctx:
        die("internal error: CNG PIN requires a use-context string", 2)
    print(f"wtssh: {ui_texts()['pin_need'].format(ctx=ctx)}", file=sys.stderr)
    sys.stderr.flush()
    proc = vault_run("unwrap-many", "\n".join(w.hex() for w in wrapped),
                     use_context=ctx)
    if proc.returncode == 2:
        die("vault key not initialized; run 'wtssh vault init' first", 4)
    if proc.returncode == 3:
        # consent refused OR a mid-batch wdek failed (PS stderr carries
        # "decrypt[i]: 0x…") -- surfacing the detail matters more in a
        # batch, where a per-key failure is not the user cancelling
        detail = (proc.stderr or "").strip()
        die("vault unlock was refused or cancelled"
            + (f": {detail}" if detail else ""), 5)
    if proc.returncode != 0:
        die(f"vault unwrap failed: {(proc.stderr or 'unknown').strip()}")
    if (proc.stderr or "").strip():
        print(f"wtssh: {proc.stderr.strip()}", file=sys.stderr)
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) != len(wrapped):
        die(f"vault unwrap returned {len(lines)} DEK(s) for "
            f"{len(wrapped)} ciphertext(s): refusing to continue", 4)
    try:
        return [bytes.fromhex(ln) for ln in lines]
    except ValueError:
        die("vault unwrap returned a malformed DEK; refusing to continue", 4)


def vault_seal(dek: bytes, plaintext: bytes, aad: str) -> bytes:
    """AES-256-GCM seal under DEK -> v2 envelope (JSON text). The AAD is the
    blob TYPE (KEY_AAD/SECRET_AAD), so a key blob can never be read as a
    passphrase blob; the owner name is bound inside the encrypted payload
    (fmt 4) and re-checked on read."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return json.dumps({
        "v": 2, "alg": "AES-256-GCM", "name": aad,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "wdek": base64.b64encode(vault_wrap(dek)).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }).encode("utf-8")


def vault_open(blob: bytes, dek: bytes, what: str = "vault blob",
               aad: str | None = None) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    obj = json.loads(blob.decode("utf-8"))
    if obj.get("v") != 2 or obj.get("alg") != "AES-256-GCM":
        raise ValueError("not a v2 vault blob")
    type_field = obj.get("name")
    if aad is not None and type_field != aad:
        die(f"{what} is a {type_field!r} blob, not {aad!r}; refusing to open "
            f"it (blob swap)", 4)
    if not type_field:
        die(f"{what} has no blob type in its envelope; re-store it "
            f"('wtssh secret set' / 'wtssh key import')", 4)
    try:
        return AESGCM(dek).decrypt(
            base64.b64decode(obj["nonce"], validate=True),
            base64.b64decode(obj["ct"], validate=True),
            type_field.encode("utf-8"))
    except InvalidTag:
        # GCM auth failure: wrong DEK, tampered ciphertext, or a blob whose
        # envelope type was edited on disk
        die(f"{what} failed authentication (corrupt, wrong vault key, or "
            f"swapped blob)", 4)
    except ValueError as e:
        # non-base64 fields slip past the envelope check only if validation is
        # skipped; be explicit rather than let a bare error escape
        die(f"{what} is corrupt: {e}", 4)


def blob_is_v2(raw: bytes) -> bool:
    return raw.lstrip().startswith(b"{")


def vault_key_path(name: str) -> Path:
    return KEYS_DIR / f"{clean_name(name)}.wtv"


def is_key_ref(key: str | None) -> bool:
    """True when an entry's --key value names a standalone vault key."""
    return bool(key) and key.startswith(KEY_REF_PREFIX)


def key_ref_name_lenient(value: str) -> str | None:
    """wtv:<name> -> <name>, or None when the spelling is unusable. Read paths
    must never die on a hand-mangled commandline: a bad reference simply is not
    a key reference. A key name becomes a file name, so file-safety applies."""
    name = value[len(KEY_REF_PREFIX):].strip()
    if not name_is_usable(name) or not key_name_is_safe(name):
        return None
    return name


def canonical_key_name(name: str) -> str | None:
    """The on-disk stem for `name`, matched case-insensitively.

    Windows filesystems are case-insensitive while our identity comparison is
    not: without this, `-i wtv:FOO` would satisfy `vault_key_path(...).exists()`
    yet fail the payload name check at connect time, and `referrers()` would
    miss the entry so `key remove foo` could delete a key that is in use."""
    want = name.lower()
    if KEYS_DIR.exists():
        for p in KEYS_DIR.glob("*.wtv"):
            if p.stem.lower() == want:
                return p.stem
    return None


def disk_key_name(name: str) -> str:
    """The spelling the rest of the program should use for key `name`: the
    on-disk stem when one matches (case-insensitively), else `name` itself, so
    dangling references stay visible as missing rather than vanishing."""
    return canonical_key_name(name) or name


def resolve_key_ref(value: str | None) -> tuple[Path, str] | None:
    """A `-i` value -> (blob path, key name) when it names a vault key.

    The only accepted spelling is `wtv:<KEYNAME>` (shlex-safe). The name is
    resolved to the on-disk spelling when a file matches. A missing key still
    resolves (the path is computed) so callers can report it instead of
    silently treating the entry as keyless.
    """
    if not value:
        return None
    v = shunquote(value)
    if not is_key_ref(v):
        return None
    name = key_ref_name_lenient(v)
    if name is None:
        return None
    name = disk_key_name(name)
    return vault_key_path(name), name


def argv_key_refs(toks: list[str]) -> list[tuple[Path, str]]:
    """Every vault key an ssh argv references, in order and de-duplicated by
    name. One place decides what "references a key" means, so connect / list /
    remove / rename cannot drift apart.

    Scanning skips argv[0] (the program name: 'ssh' for plain entries, the
    quoted shim path for routed entries) and stops at the destination (the
    first bare token that is NOT an option value), exactly like `cmd_fields`:
    a `-i` inside a REMOTE command (`ssh host grep -i x`) is not a key
    reference and must not make the entry look multi-key. Value-taking
    options (`VALUE_OPTS`) consume the following token, so `-i wtv:x` must
    not have its VALUE mistaken for the destination."""
    out: list[tuple[Path, str]] = []
    seen: set[str] = set()
    i = 1
    while i < len(toks):
        t = toks[i]
        if not t.startswith("-"):
            break  # the destination; everything after is a remote command
        if t in VALUE_OPTS and i + 1 < len(toks):
            if t == "-i":
                ref = resolve_key_ref(toks[i + 1])
                if ref is not None and ref[1] not in seen:
                    seen.add(ref[1])
                    out.append(ref)
            i += 2  # option + value, then keep scanning
            continue
        i += 1  # boolean flag (-4, -A); attached-value forms ride in extra
    return out


def entry_key_refs(line: str) -> list[tuple[Path, str]]:
    """argv_key_refs for a stored commandline (lenient tokenizing)."""
    return argv_key_refs(toks_lenient(line))


def has_lexical_key_ref(line: str) -> bool:
    """True when any `-i wtv:...` token appears lexically in the line, BEFORE
    reference semantics are applied (lenient parsing refuses poisoned
    spellings). Used by the mutual-exclusion checks: a stored passphrase plus
    a vault-key reference must not coexist even when the reference is too
    mangled (or cmd-poisoned) to resolve -- connect dispatches exactly one
    passphrase by refs, so a degraded reference must not silently coexist
    with a secret."""
    return any(resolve_key_ref(t) is not None
               for t in toks_lenient(line)) \
        or bool(re.search(r"(?i)-i\s+['\"]?wtv:", line))


def profile_key_refs(p: dict) -> list[tuple[Path, str]]:
    """entry_key_refs for a profile: lenient from end to end, so a mangled
    commandline cannot poison read-only commands (list/key list/...)."""
    return entry_key_refs(plain_line_lenient(p))


def referrers(data: dict, keyname: str) -> list[str]:
    """Entry names whose commandline -i references the standalone key
    `keyname` (`-i wtv:<keyname>`). Names are compared in their on-disk
    spelling, so case cannot hide a user."""
    keyname = disk_key_name(keyname)   # self-contained: callers may pass any case
    out = []
    for p in data["profiles"]["list"]:
        if not str(p.get("name", "")).startswith(PREFIX):
            continue
        if any(name == keyname for _path, name in profile_key_refs(p)):
            out.append(p["name"][len(PREFIX):])
    return out


def toks_lenient(line: str) -> list[str]:
    """ssh_tokens that never dies (read/inspect paths must tolerate a
    hand-mangled commandline)."""
    try:
        return ssh_tokens(line)
    except ValueError:
        return line.split()


def plain_line_lenient(p: dict) -> str:
    """plain_line that never dies: same "strip the routed header" job, but a
    commandline whose quotes cannot be round-tripped comes back raw instead of
    killing the whole command. Write paths use strict_tokens_or_die instead, so
    a line they cannot faithfully rebuild fails with a message, not a
    traceback."""
    line = p.get("commandline") or ""
    toks = toks_lenient(line)
    if is_routed(toks) and "--" in toks:
        return " ".join(toks[toks.index("--") + 1:])
    return line


def strict_tokens_or_die(p: dict, line: str | None = None) -> list[str]:
    """ssh_tokens for WRITE paths and for connect.

    A commandline whose quotes cannot be round-tripped must die with the same
    actionable message `list`/`edit` already give (`cmd_fields` wording), never
    with a bare ValueError traceback. `line` overrides the source: connect
    wants the RAW stored commandline (it strips the routed header itself),
    while the rewriting loops want the plain ssh tokens."""
    try:
        if line is None:
            return ssh_tokens(plain_line(p))
        return ssh_tokens(line)
    except ValueError as e:
        die(f"{e} in entry '{p.get('name', '?')}'; fix or remove it first")


def vault_meta_path() -> Path:
    return SECRETS_DIR / "vault.json"


def vault_load_blob(raw: bytes, what: str, want: str) -> dict:
    """Parse+validate a v2 envelope. `want` is the blob type it must carry
    (KEY_AAD/SECRET_AAD). A file that is not a v2 envelope is refused with an
    actionable message *before* any dialog pops (an unrecognized file is
    foreign or damaged)."""
    if not blob_is_v2(raw):
        die(f"{what} is not a vault blob (retired DPAPI file or foreign "
            f"file); re-store it ('wtssh secret set' / 'wtssh key import') "
            f"under the vault", 4)
    try:
        obj = json.loads(raw.decode("utf-8"))
        if obj.get("v") != 2 or obj.get("alg") != "AES-256-GCM":
            raise ValueError("bad version/alg")
        # validate=True: a non-base64 string must fail HERE, as a corrupt file,
        # rather than silently decoding to b"" and blowing up later in
        # vault_open() as a bare ValueError (binascii.Error is a ValueError).
        base64.b64decode(obj["nonce"], validate=True)
        base64.b64decode(obj["wdek"], validate=True)
        base64.b64decode(obj["ct"], validate=True)
    except (ValueError, KeyError) as e:
        die(f"{what} is corrupt: {e}", 4)
    if obj.get("name") != want:
        if obj.get("name") in (KEY_AAD, SECRET_AAD):
            die(f"{what} is a {obj['name']!r} blob, not {want!r}; refusing "
                f"to open it (blob swap)", 4)
        fix = ("'wtssh key remove NAME' + 'wtssh key import NAME <file>'"
               if want == KEY_AAD else "'wtssh secret set NAME'")
        die(f"{what} carries an unknown envelope type "
            f"({obj.get('name')!r}); re-store it: {fix}", 4)
    return obj


def vault_open_blob(obj: dict, what: str = "vault blob",
                    aad: str | None = None, use_context: str = "",
                    dek: bytes | None = None) -> bytes:
    """wdek -> CNG consent dialog -> DEK -> AES-GCM open. Interactive --
    unless the caller batch-unwraps up front (chain connect: one consent
    gesture for the whole chain) and hands the DEK in."""
    if dek is None:
        dek = vault_unwrap(base64.b64decode(obj["wdek"]), use_context)
    return vault_open(json.dumps(obj).encode("utf-8"), dek, what, aad)


def vault_open_payload(kind: str, name: str, raw: bytes, what: str,
                       use_context: str, dek: bytes | None = None) -> dict:
    """The whole read path for a name-bound blob: envelope type -> CNG PIN
    -> decrypt -> payload fmt and payload['name'] check. The name check is
    the anti-swap guarantee: a blob copied from another name is
    refused even though its DEK unwraps, because it names a different one.
    Chain connect passes `dek` (batch-unwrapped, one consent gesture);
    every other caller unwraps per blob here."""
    obj = vault_load_blob(raw, what, kind)
    pt = vault_open_blob(obj, what, kind, use_context, dek=dek)
    try:
        payload = json.loads(pt.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        die(f"{what} payload is not valid JSON", 4)
    fmt = payload.get("fmt") if isinstance(payload, dict) else None
    if fmt != PAYLOAD_FMT:
        die(f"{what} payload has an unsupported format; re-store it "
            f"('wtssh secret set NAME' / 'wtssh key remove NAME' + "
            f"'wtssh key import NAME <file>')", 4)
    if payload.get("name") != name:
        die(f"{what} belongs to {payload.get('name')!r}, not "
            f"{name!r}; blob swap refused", 4)
    return payload


def reseat_blob(kind: str, old: str, new: str, src: Path, dst: Path,
                what: str, use_context: str) -> None:
    """Re-seal a name-bound blob for its new name: same payload, fresh DEK,
    payload['name'] rewritten (one CNG PIN dialog). The caller removes the
    old file only after the settings write succeeded."""
    payload = vault_open_payload(kind, old, src.read_bytes(), what, use_context)
    payload["name"] = new
    atomic_write(dst, vault_seal(secrets.token_bytes(32),
                                 json.dumps(payload).encode("utf-8"), kind))


def drop_blobs(paths: list[Path]) -> None:
    """Remove freshly written blobs whose settings write did not happen.
    Failure is a warning, not fatal: the caller is already unwinding."""
    for f in paths:
        try:
            f.unlink()
        except OSError as e:
            print(f"wtssh: warning: could not drop {f}: {e} -- remove it "
                  f"manually", file=sys.stderr)


def routed_line(name: str, p: dict) -> str:
    """commandline routing the tab through the vault; the
    original ssh tokens are embedded after '--' so list/edit keep working
    (single source). The launcher is the installed wtssh.cmd shim: a moved
    or reinstalled interpreter cannot orphan existing tabs.

    Wrapping must not re-parse strictly: `plain_line` dies on a commandline
    whose quotes cannot be round-tripped, which would turn every routed write
    (add/edit/key import/key rename/key remove --force/secret set/secret
    remove) into a bare traceback for such an entry. The lenient variant wraps
    it verbatim instead -- the same tolerance the read paths already have, and
    `list` still tells the user to fix it. Both the name and the embedded
    payload are screened for cmd metacharacters (CMD_UNSAFE_CHARS /
    PAYLOAD_UNSAFE_CHARS): a routed line is launched via cmd.exe, and either
    half can carry an injection."""
    plain = plain_line_lenient(p)
    if not cmd_name_is_safe(name):
        # choke point: every caller is a write path, so no code path can
        # (re)emit a cmd-unsafe name into a routed line. Legacy entries get
        # here via edit/secret set/key rename -- the fix is a rename.
        die(f"entry name '{name}' contains cmd metacharacters; a routed tab "
            f"would run them via cmd.exe when it opens -- rename the entry "
            f"first: wtssh rename '{name}' <safe-name>")
    bad = cmd_risky_payload_chars(plain)
    if bad:
        # the embedded ssh command is just as exposed to the cmd.exe layer
        # as the name (host/user/options/remote command): a hostile ssh
        # config simply moves the payload out of the alias, so filtering
        # aliases alone would not close the channel
        die(f"the ssh command routed for '{name}' carries cmd metacharacters "
            f"{' '.join(repr(c) for c in bad)}; a routed tab runs it via "
            f"cmd.exe, where they would split or expand the commandline -- "
            f"remove them (host/user/options/remote command) or keep the "
            f"entry vault-free")
    return (f"{shquote(str(shim_path()))} connect {shquote(name)} "
            f"-- {plain}")


def plain_line(p: dict) -> str:
    """commandline with any connect wrapper stripped.

    Strict by design: it raises ValueError on a line whose quotes cannot be
    round-tripped, so it is only for callers that report that properly --
    `strict_tokens_or_die`. Read-only commands use
    `plain_line_lenient` instead."""
    line = p.get("commandline") or ""
    toks = ssh_tokens(line)
    if is_routed(toks):
        return " ".join(toks[toks.index("--") + 1:])
    return line


def secret_store(name: str, passphrase: str):
    """Seal a passphrase under a fresh random DEK; the DEK is RSA-OAEP
    wrapped by the TPM vault key (silent public-key op)."""
    if not vault_exists():
        die("vault is not initialized; run 'wtssh vault init' first", 4)
    if secret_path(name).stem != name.strip():
        # an entry name with '/'/'\\' would silently collide with a legal 'a_b'
        # entry after sanitizing -- refuse instead (rename first)
        die(f"entry name '{name}' is not usable for secret storage; "
            f"rename it first (wtssh rename {name!r} <new-name>)")
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"fmt": PAYLOAD_FMT, "name": name,
                          "passphrase": passphrase}).encode("utf-8")
    atomic_write(secret_path(name),
                 vault_seal(secrets.token_bytes(32), payload, SECRET_AAD))


def secret_load(name: str, use_context: str) -> str | None:
    """Open a vault-encrypted passphrase. Interactive: the CNG consent
    dialog (TPM PIN) pops before the DEK is released."""
    p = secret_path(name)
    if not p.exists():
        return None
    payload = vault_open_payload(SECRET_AAD, name, p.read_bytes(),
                                 f"secret '{name}'", use_context)
    pw = payload.get("passphrase")
    if not isinstance(pw, str):
        die(f"secret '{name}' payload has a corrupt passphrase field", 4)
    return pw



def read_passphrase(prompt: str) -> str:
    """Hidden prompt on a real console; single stdin line when piped
    (getpass deadlocks on non-console stdin under Windows)."""
    if sys.stdin is not None and sys.stdin.isatty():
        import getpass
        return getpass.getpass(prompt)
    line = sys.stdin.readline()
    return line.rstrip("\r\n")

# ---------------------------------------------------------------- key import

def key_encrypted(path: Path) -> bool | None:
    """True/False by actually parsing the key format; None when the file is
    not a recognizable private key. (Probing via ssh-keygen is unusable: an
    encrypted key makes it block reading a passphrase from the terminal.)
    OpenSSH container: base64 body decodes to 'openssh-key-v3\\0' magic,
    then two length-prefixed strings -- ciphername first; 'none' means
    unencrypted. PEM: 'Proc-Type: 4,ENCRYPTED' header line."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        die(f"cannot read key '{path}': {e}")
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in text:
        body = "".join(
            l for l in text.splitlines()
            if l and not l.startswith("-----"))
        try:
            import base64
            raw = base64.b64decode("".join(body.split())[:800], validate=False)
        except ValueError:
            return None
        magic = b"openssh-key-v1\x00"  # container magic ssh-keygen emits
        if not raw.startswith(magic):
            return None

        def ssh_string(buf: bytes, off: int) -> tuple[bytes, int]:
            n = int.from_bytes(buf[off:off + 4], "big")
            return buf[off + 4:off + 4 + n], off + 4 + n

        cipher, _ = ssh_string(raw, len(magic))
        return cipher != b"none"
    if "-----BEGIN ENCRYPTED PRIVATE KEY-----" in text:
        return True  # PKCS#8 encrypted container: encrypted by definition
    if any(h in text for h in ("BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY",
                               "BEGIN EC PRIVATE KEY", "BEGIN PRIVATE KEY")):
        return "ENCRYPTED" in text


# ---------------------------------------------------------------- ui texts
# Copy for the native dialogs. zh is the default; WTSSH_UI_LANG=en switches
# the dialogs only (CLI output stays JSON/English either way).
UI_TEXTS = {
    "zh": {
        "pass": "私钥口令短语",
        "entry": "条目：{name}",
        "confirm": "再输入一遍以确认",
        "mismatch": "两次输入不一致，请重新输入",
        "ok": "确定",
        "cancel": "取消",
        "pin_need": "需要 TPM PIN — {ctx}",
        "hostkey_dialog": "wtssh：未知主机的 host key。请核对指纹后选择是否接受：",
        "pin_connect": "连接主机 {name}（{dest}）",
        "pin_connect_key": "连接主机 {name}（{dest}），使用密钥 {key}",
        "pin_chain_batch": "连接 {name}（{dest}）：解封密钥 {keys}",
        "pin_agent_load": "加载密钥到 ssh-agent（有效期 {dest}）：解封密钥 {keys}",
        "pin_tunnel_batch": "为 FileZilla 建立隧道并导出会话密钥（条目 {name}，经 {dest}）：解封密钥 {keys}",
        "pin_export": "导出密钥 {key}",
        "pin_filezilla_export": "为 FileZilla 导出连接密钥 {key}（条目 {name}，口令随机生成、仅本次会话有效）",
        "pin_rename_key": "重命名密钥 {old} → {new}",
        "pin_rename_secret": "重命名条目 {old} → {new} 的口令",
        "pin_filezilla_password": "为 FileZilla 复制登录口令（条目 {name}，{dest}）",
        "clip_confirm_title": "确认复制登录口令到剪贴板",
        "clip_confirm_body": "条目 {name}（{dest}）的登录口令将复制到剪贴板，供粘贴进 FileZilla 的密码框。\n\n剪贴板不是秘密通道：同用户任意进程可读取；Win+V 历史/云同步/RDP 剪贴板会把它带走；本工具不自动清空。请粘贴后尽快覆盖清除，且不要勾选 FileZilla 的“记住密码”。\n\n口令永不打印到终端/JSON/日志。确认复制吗？",
    },
    "en": {
        "pass": "Private key passphrase",
        "entry": "Entry: {name}",
        "confirm": "Re-enter the passphrase to confirm",
        "mismatch": "The two entries differ; try again",
        "ok": "OK",
        "cancel": "Cancel",
        "pin_need": "TPM PIN required — {ctx}",
        "hostkey_dialog": "wtssh: unknown host key. Verify the fingerprint, then choose whether to accept:",
        "pin_connect": "connect to host {name} ({dest})",
        "pin_connect_key": "connect to host {name} ({dest}) using key {key}",
        "pin_chain_batch": "connect to {name} ({dest}): unlock keys {keys}",
        "pin_agent_load": "load keys into ssh-agent (valid {dest}): unlock keys {keys}",
        "pin_tunnel_batch": "tunnel for FileZilla + export its session key (entry {name} via {dest}): unlock keys {keys}",
        "pin_export": "export key {key}",
        "pin_filezilla_export": "export the FileZilla connection key {key} (entry {name}; random passphrase, this session only)",
        "pin_rename_key": "rename key {old} → {new}",
        "pin_rename_secret": "rename entry {old} → {new} passphrase",
        "pin_filezilla_password": "copy login password for FileZilla (entry {name}, {dest})",
        "clip_confirm_title": "Confirm copying the login password to the clipboard",
        "clip_confirm_body": "The login password for entry {name} ({dest}) will be copied to the clipboard for pasting into FileZilla's password prompt.\n\nThe clipboard is not a secret channel: any same-user process can read it; Win+V history/cloud sync/RDP clipboard will carry it away; this tool does not auto-clear it. Overwrite it right after pasting, and do not tick FileZilla's 'Remember password'.\n\nThe password is never printed to the terminal/JSON/logs. Copy it?",
    },
}


def ui_texts() -> dict:
    return UI_TEXTS.get(os.environ.get("WTSSH_UI_LANG", "zh"), UI_TEXTS["zh"])


def run_passphrase_dialog(title: str, entry_name: str, confirm: bool) -> str:
    """Capture a passphrase through the WPF dialog and get it back as
    plaintext ONLY via in-process DPAPI round-trip: the dialog prints a
    base64 ciphertext, we unprotect it here. With stdin non-tty (agent-
    driven sessions) this keeps the passphrase off any LLM-visible pipe."""
    t = ui_texts()
    cmd = [resolve_bin("powershell"), "-NoProfile", "-ExecutionPolicy",
           "Bypass",
           "-File", str(SCRIPTS / "passphrase-prompt.ps1"),
           "-Title", title,
           "-EntryHint", t["entry"].format(name=entry_name),
           "-PassLabel", t["pass"],
           "-ConfirmLabel", t["confirm"],
           "-MismatchLabel", t["mismatch"],
           "-OkLabel", t["ok"],
           "-CancelLabel", t["cancel"]]
    if confirm:
        cmd.append("-Confirm")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 2:
        die("passphrase entry cancelled", 2)
    if proc.returncode != 0:
        die(f"passphrase dialog failed: {(proc.stderr or '').strip()}")
    return dpapi("Unprotect", proc.stdout.strip())


def gui_passphrase(title: str, entry_name: str) -> str:
    """Single-box capture. title names the action that raised the dialog
    ('wtssh key import' / 'wtssh secret set'), so the window never claims
    to be a different command than the one being run. Import verifies the
    passphrase against the source key, so a typo costs a retry, not a
    wrong sealed secret."""
    return run_passphrase_dialog(title, entry_name, False)


def gui_passphrase_confirm(entry_name: str) -> str:
    """Same native capture, but with a second confirmation box; the dialog
    itself enforces that both entries match before returning."""
    return run_passphrase_dialog("wtssh key export", entry_name, True)


def _load_private_key(keydata: bytes, passphrase: bytes | None):
    """In-process private-key parse. Tries PEM containers first (PKCS#1/
    PKCS#8), then the OpenSSH container (load_pem_private_key REJECTS
    'BEGIN OPENSSH PRIVATE KEY' blocks, so both loaders are needed for
    ssh-keygen-format parity). passphrase None = unencrypted source."""
    from cryptography.hazmat.primitives import serialization
    try:
        return serialization.load_pem_private_key(keydata, passphrase)
    except ValueError:
        return serialization.load_ssh_private_key(keydata, passphrase)


def rekey_bytes(keydata: bytes, old_pw: str | None, new_pw: str) -> bytes:
    """Decrypt + re-encrypt a private key entirely in memory (OpenSSH
    container, BestAvailableEncryption). Replaces the old ssh-keygen -p
    workdir flow: no temp file, no argv, no plaintext on disk. old_pw
    None/'' means the source is unencrypted."""
    from cryptography.hazmat.primitives import serialization
    key = _load_private_key(
        keydata, old_pw.encode("utf-8") if old_pw else None)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.BestAvailableEncryption(
            new_pw.encode("utf-8")))


def verify_passphrase(keydata: bytes, passphrase: str) -> bool:
    """True when the passphrase decrypts the key (in-process parse; no
    subprocess, no env/argv exposure)."""
    from cryptography.exceptions import UnsupportedAlgorithm
    try:
        _load_private_key(
            keydata, passphrase.encode("utf-8") or None)
        return True
    except (TypeError, ValueError):
        return False
    except UnsupportedAlgorithm as e:
        die(f"cannot parse this key container: {e} (the 'bcrypt' package "
            f"is required for OpenSSH-format keys)", 5)


def argv_option_slots(toks: list[str]) -> tuple[int, list[tuple[int, int]]]:
    """(start, slots) for the OPTION region of an ssh argv.

    `start` is the index just after the program name. A slot is
    `(index, width)`: width 2 for an option that consumes the next token, 1 for
    a lone flag or attached value. The region ends at the destination (or at
    `--`), so a `-i` belonging to a REMOTE command (`ssh host uptime -i x`) is
    never inside it -- the one place that decides that boundary for the
    rewriting helpers, matching `argv_key_refs`.

    The program name is `shunquote`d before basename, exactly like
    `is_routed`/`ssh_argv`: a hand-written line can point at a quoted
    `"C:\\Program Files\\OpenSSH\\ssh.exe"`, and mistaking it for a
    non-program token put `start` at 0 (i.e. `-i` in front of the program)."""
    start = 1 if toks and \
        os.path.basename(shunquote(toks[0])).lower().removesuffix(".exe") == "ssh" \
        else 0
    slots: list[tuple[int, int]] = []
    i = start
    while i < len(toks):
        t = toks[i]
        if t == "--" or not t.startswith("-"):
            break
        if t in VALUE_OPTS and i + 1 < len(toks):
            slots.append((i, 2))
            i += 2
        else:
            slots.append((i, 1))
            i += 1
    return start, slots


def set_key_option(toks: list[str], ref: str) -> list[str]:
    """Put `-i <ref>` into the OPTION region, REPLACING an existing `-i`.

    Replacing (not appending) is what makes `key import NAME` re-point an entry
    that already had an identity: appending would leave `-i wtv:new -i <old>`
    behind, which either makes connect fail closed on "2 vault keys" or
    silently falls back to a plaintext key file. Only the option region is
    touched, so a remote command's own `-i` survives."""
    start, slots = argv_option_slots(toks)
    for idx, width in slots:
        if toks[idx] == "-i":
            if width == 2:
                toks[idx + 1] = ref
            else:                     # `ssh -i` with no value: repair in place
                toks.insert(idx + 1, ref)
            return toks
    toks[start:start] = ["-i", ref]
    return toks


def option_region_start(toks: list[str]) -> int:
    """Index of the first option token (just past the program name) -- the
    same boundary argv_option_slots draws. Command-line -o options are
    FIRST-obtained-wins (verified: `ssh -G -o BatchMode=yes -o BatchMode=no`
    yields yes), so hardening options inserted HERE cannot be overridden by
    any user `-o` later in the same line."""
    return argv_option_slots(toks)[0]


def action_key_import(args):
    """Import a private key file into the vault as a STANDALONE key.

    Both encrypted and unencrypted sources are re-encrypted IN MEMORY into an
    OpenSSH container under a random one-shot session passphrase
    (cryptography; no ssh-keygen subprocess, no temp file, no argv) -- only
    that container plus the session passphrase are sealed as one AES-256-GCM
    blob, so no key material ever touches disk outside the vault. An
    unencrypted source gains both at-rest and runtime encryption at import
    time (the original bytes are not kept); connect's %TEMP% always holds an
    encrypted container.

    The key is `keys/<KEYNAME>.wtv` and needs no host entry. If an entry with
    the same name exists, its identity is re-pointed at the new key
    (`-i wtv:<KEYNAME>`).
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    keyname = checked_key_name(args.name)
    src = Path(args.keyfile).expanduser()
    if not src.is_file():
        die(f"key file not found: {src}")
    enc = key_encrypted(src)
    if enc is None:
        die(f"not a recognized private key: {src}")
    data = load()
    entry = find_profile(data, keyname)
    if entry is not None and secret_path(keyname).exists():
        die(f"entry '{keyname}' already has a stored passphrase; the "
            f"passphrase of an imported key lives inside its vault blob. "
            f"Run 'wtssh secret remove {keyname}' first")
    if entry is not None:
        # the same-name entry will be re-pointed at the new key below; refuse
        # BEFORE any dialog or blob write if that rewrite would fail, or the
        # freshly sealed key blob would be orphaned
        bad = cmd_risky_payload_chars(plain_line_lenient(entry))
        if bad:
            die(f"existing entry '{keyname}' carries cmd metacharacters "
                f"{' '.join(repr(c) for c in bad)} in its ssh command; it "
                f"cannot be re-pointed at the new key -- fix the entry first "
                f"('wtssh edit {keyname}' / rename) and retry the import")
    if not vault_exists():
        die("vault is not initialized; run 'wtssh vault init' first", 4)
    dest = vault_key_path(keyname)
    if dest.exists():
        # Fast-fail before any passphrase dialog; re-checked under the Lock
        # below, because two same-name imports can both pass this pre-check
        # and the later atomic_write would silently overwrite.
        die(f"vault key '{keyname}' already exists ('wtssh key list' shows "
            f"them); rename it ('wtssh key rename {keyname} <new>') or remove "
            f"it ('wtssh key remove {keyname}') first")
    src_bytes = src.read_bytes()
    passphrase = None
    if enc:
        for _ in range(3):
            passphrase = gui_passphrase("wtssh key import", keyname)
            if verify_passphrase(src_bytes, passphrase):
                break
            print("wtssh: passphrase incorrect; try again",
                  file=sys.stderr)
        else:
            die("passphrase verification failed after 3 attempts", 5)
    try:
        session_pw = secrets.token_urlsafe(32)  # one-shot, sealed in blob
        container = rekey_bytes(
            src_bytes, passphrase if enc else None, session_pw)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        die("failed to re-encrypt the key (wrong passphrase or "
            "unsupported format)", 5)
    # Seal AND land the blob under the same lock the destructive vault ops
    # hold: a concurrent `vault remove` must either wait (its blob guard
    # then sees this blob and refuses) or have finished (vault_wrap below
    # then fails loudly) -- no blob may end up referencing a dead key. No
    # dialog runs in this section, so holding the lock is cheap.
    bound = None
    with Lock():
        # Re-check under the lock: the pre-check above raced with concurrent
        # same-name imports (both pass, later write silently wins).
        if dest.exists():
            die(f"vault key '{keyname}' already exists ('wtssh key list' "
                f"shows them); rename it ('wtssh key rename {keyname} <new>') "
                f"or remove it ('wtssh key remove {keyname}') first")
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            "fmt": PAYLOAD_FMT,
            "name": keyname,
            "key": base64.b64encode(container).decode("ascii"),
            "passphrase": session_pw,
        }).encode("utf-8")
        atomic_write(dest, vault_seal(secrets.token_bytes(32), payload, KEY_AAD))
        if entry is not None:
            try:
                data = load()
                p = require_profile(data, keyname)
                toks = strict_tokens_or_die(p)
                ref = shquote(f"{KEY_REF_PREFIX}{keyname}")
                set_key_option(toks, ref)
                ensure_shim()          # routed lines point at it, so it must exist
                p["commandline"] = routed_line(keyname,
                                               {"commandline": " ".join(toks)})
                save(data)
            except BaseException:
                # the bind died after the blob was already sealed (an unround-
                # trippable commandline, a poisoned payload the lenient pre-check
                # missed, a save failure): drop the orphan blob so the failed
                # import is a clean no-op. Deleting is safe ONLY because the
                # --move source wipe runs after this block -- a failed import
                # never eats the plaintext source (the blob without the wipe
                # would also be recoverable via 'key list', but a clean rollback
                # beats leaving a key the user was told did not import).
                drop_blobs([dest])
                raise
            bound = keyname
    if getattr(args, "move", False):
        # wipe the plaintext source: the vault copy supersedes it. Failure
        # is loud -- a half-wiped key file must not pass silently. Runs AFTER
        # the bind so a bind failure rolls back to "source intact, no blob".
        try:
            size = src.stat().st_size
            with open(src, "r+b") as f:
                f.write(b"\x00" * size)
            src.unlink()
        except OSError as e:
            die(f"imported OK but failed to remove source key {src}: {e} "
                f"-- remove it manually (plaintext copy remains)", 5)
    print(json.dumps({"ok": True, "key": keyname, "encrypted": enc,
                      "vaultKey": str(dest), "boundEntry": bound},
                     ensure_ascii=False))


def action_key_list(args):
    """Standalone vault keys and which entries reference each one. No PIN:
    the inventory comes from filenames and command lines, never from opening
    a blob."""
    data = load()
    keys = (sorted(p.stem for p in KEYS_DIR.glob("*.wtv"))
            if KEYS_DIR.exists() else [])
    rows = [{"key": k, "referrers": referrers(data, k)} for k in keys]
    print(json.dumps({"keys": rows}, ensure_ascii=False))


def action_key_rename(args):
    """Rename a standalone vault key and re-point every referencing entry.

    Ordering mirrors action_rename: re-seal first (one CNG PIN), then swap
    settings under the Lock, then delete the old blob. A failure inside the
    Lock drops the fresh copy and leaves the old key live."""
    old, new = disk_key_name(checked_key_name(args.old)), checked_key_name(args.new)
    if old == new:
        die("old and new key names are identical")
    if disk_key_name(new) == old:
        die(f"'{new}' differs from '{old}' only by case, and this filesystem "
            f"is case-insensitive -- that is the same key file")
    kp_old, kp_new = vault_key_path(old), vault_key_path(new)
    if not kp_old.exists():
        die(f"no vault key named '{old}' ('wtssh key list' shows them)")
    if kp_new.exists():
        die(f"vault key '{new}' already exists")
    # re-seal before the Lock: the CNG PIN dialog blocks (same reasoning as
    # action_rename); vault_open_payload checks the payload name against the old
    # key name on the way in.
    reseat_blob(KEY_AAD, old, new, kp_old, kp_new, f"key '{old}'",
                pin_text("pin_rename_key", old=old, new=new))
    try:
        with Lock():
            data = load()
            # Re-derive referrers INSIDE the Lock: the PIN dialog above can
            # block for a while, and an `edit --key wtv:<old>` landing in
            # that window must not be left dangling.
            touched = referrers(data, old)
            for name in touched:
                p = find_profile(data, name)
                if p is None:
                    continue
                toks = strict_tokens_or_die(p)
                changed = False
                # only the OPTION region, so a remote command's own `-i` is
                # left alone (same boundary as argv_key_refs / key remove)
                _start, slots = argv_option_slots(toks)
                for idx, width in slots:
                    if toks[idx] != "-i" or width != 2:
                        continue
                    ref = resolve_key_ref(toks[idx + 1])
                    if ref is None or ref[1] != old:
                        continue
                    # only one spelling exists (`wtv:`), so rewriting the value
                    # is the whole job
                    toks[idx + 1] = shquote(f"{KEY_REF_PREFIX}{new}")
                    changed = True
                if changed:
                    ensure_shim()      # routed lines point at it
                    p["commandline"] = routed_line(
                        name, {"commandline": " ".join(toks)})
            save(data)
    except BaseException:
        # settings.json was never replaced: the fresh blob is an orphan and
        # the old key is still the live one. Re-sealing is repeatable.
        drop_blobs([kp_new])
        raise
    try:
        kp_old.unlink(missing_ok=True)
    except OSError as e:
        # settings.json already points at the new key, so the old blob is
        # merely unused now; warn instead of failing a completed rename (and
        # leave the user a path to remove it by hand)
        print(f"wtssh: warning: could not remove old key blob {kp_old}: {e} "
              f"-- remove it manually (the rename itself succeeded)",
              file=sys.stderr)
    print(json.dumps({"ok": True, "renamed": f"{old} -> {new}",
                      "repointed": touched}, ensure_ascii=False))


def action_key_export(args):
    """Export a standalone vault key back to a passphrase-protected file.
    Consent chain: the CNG PIN releases the blob, then a native dialog
    collects the NEW passphrase (with confirmation). The key is
    re-encrypted from its one-shot session passphrase to the user's passphrase
    entirely in memory (cryptography), then written atomically to the target
    with the owner-only DACL applied to the TEMP file BEFORE any content
    exists (atomic_write_owner_only; same discipline as the key containers)
    -- no sibling workdir, and the only intermediate (.wtssh.*.tmp) holds
    the final ciphertext itself. No plaintext key ever lands on disk."""
    keyname = disk_key_name(checked_key_name(args.name))
    src = vault_key_path(keyname)
    if not src.exists():
        die(f"no vault key named '{keyname}' ('wtssh key list' shows them)")
    out = Path(args.outfile).expanduser()
    if out.exists():
        die(f"refusing to overwrite existing file: {out}", 4)
    # fail early, BEFORE any dialogs: if the target dir can't even be
    # created, don't make the user click through PIN+passphrase
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        die(f"cannot create output directory {out.parent}: {e}", 4)
    payload = vault_open_payload(KEY_AAD, keyname, src.read_bytes(),
                                 f"key '{keyname}'",
                                 pin_text("pin_export", key=keyname))
    container_b64 = payload.get("key")
    session_pw = payload.get("passphrase")
    if not isinstance(container_b64, str) or not isinstance(session_pw, str):
        die(f"key '{keyname}' payload is missing its key material; "
            f"re-import it ('wtssh key remove {keyname}' + "
            f"'wtssh key import {keyname} <file>')", 4)
    container = base64.b64decode(container_b64)
    new_pw = gui_passphrase_confirm(keyname)
    if not new_pw:
        # BestAvailableEncryption rejects empty passphrases; an exported
        # file must be passphrase-protected (SKILL contract)
        die("empty passphrase; export refuses to write an unencrypted "
            "key file", 4)
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        out_bytes = rekey_bytes(container, session_pw, new_pw)
    except (TypeError, ValueError, UnsupportedAlgorithm) as e:
        die(f"failed to re-encrypt the key for export: {e}", 5)
    try:
        # owner-only DACL lands on the TEMP file BEFORE any content exists:
        # a plain atomic_write would expose the exported key under the
        # target directory's inherited ACL until a post-hoc tighten ran.
        # A genuine DACL failure is fatal here (fail-closed, same as the
        # askpass map); the acknowledged opt-out is WTSSH_ALLOW_LOOSE_ACL=1,
        # which makes apply_owner_only_dacl degrade to chmod + warning
        # instead of raising.
        atomic_write_owner_only(out, out_bytes)
    except OSError as e:
        die(f"cannot write {out}: {e}", 4)
    print(json.dumps({"ok": True, "exported": keyname,
                      "file": str(out)}, ensure_ascii=False))


def action_key_remove(args):
    """Delete a standalone vault key. Refused while any entry references it:
    silently orphaning an `-i wtv:<name>` would leave that entry unable to
    authenticate with a confusing error. --force strips those references."""
    keyname = disk_key_name(checked_key_name(args.name))
    dest = vault_key_path(keyname)
    if not dest.exists():
        die(f"no vault key named '{keyname}' ('wtssh key list' shows them)")
    data = load()
    users = referrers(data, keyname)
    force = bool(getattr(args, "force", False))

    def refuse(still: list[str]):
        die(f"vault key '{keyname}' is still referenced by: "
            f"{', '.join(still)} -- re-point them first ('wtssh edit <entry> "
            f"--key <path|wtv:KEYNAME|none>') or pass --force to drop those "
            f"references", 4)

    if users and not force:
        refuse(users)          # fast fail without taking the lock
    with Lock():
        # The AUTHORITATIVE check runs inside the Lock: an `edit --key
        # wtv:<key>` landing between the snapshot above and this write would
        # otherwise be deleted blind (that is the R3 window `key rename`
        # already closes the same way).
        data = load()
        users = referrers(data, keyname)
        if users and not force:
            refuse(users)
        for name in users:
            p = find_profile(data, name)
            if p is None:
                continue
            toks = strict_tokens_or_die(p)
            _start, slots = argv_option_slots(toks)
            drop: set[int] = set()
            for idx, width in slots:
                if toks[idx] != "-i" or width != 2:
                    continue
                ref = resolve_key_ref(toks[idx + 1])
                if ref is not None and ref[1] == keyname:
                    drop.update((idx, idx + 1))
            # only the OPTION region is scanned, so a remote command keeps its
            # own `-i` (a blind scan ate `grep -i wtv:foo` down to `grep`)
            line = " ".join(t for i, t in enumerate(toks) if i not in drop)
            ensure_shim()      # routed lines point at it
            p["commandline"] = routed_line(name, {"commandline": line})
        if users:              # nothing changed if the window was empty
            save(data)
    if dest.exists():
        try:
            dest.unlink()
        except OSError as e:
            # The references above are already saved, but the KEY is still
            # there, so the state is recoverable and the message says how.
            # (key rename warns in the same spot; failing hard here would
            # report an error after an irreversible settings write.)
            die(f"references to key '{keyname}' were dropped, but the key "
                f"blob {dest} could not be deleted: {e} -- remove it manually; "
                f"re-import the key if that removal was a mistake", 5)
    print(json.dumps({"ok": True, "key": keyname,
                      "unreferenced": users}, ensure_ascii=False))


# ------------------------------------------------- ssh-agent cache (PIN once)
#
# Why an agent at all: every connect currently costs exactly one CNG PIN.
# The agent holds DECRYPTED keys in ssh-agent memory for a
# bounded TTL, so tabs opened inside the window connect with no PIN. The
# long-ago D4 "no resident daemon" call does not apply: the daemon is
# Microsoft's ssh-agent, not ours -- no new IPC, no new single-writer
# protocol (we only ever add/remove keys by fingerprint).
#
# Two hard-won facts shape the design (both verified on this machine):
#   1. Windows ssh-add NEVER consults SSH_ASKPASS -- it reads the key
#      passphrase from the console unconditionally, so a
#      passphrase-protected container cannot be added headlessly. `agent
#      load` therefore re-serializes the key UNENCRYPTED in Python
#      (cryptography) into one owner-only temp file, adds THAT, and
#      overwrite-wipes it immediately. The steady-state exposure is the
#      agent's memory for the TTL; the load instant additionally exposes
#      cleartext in our process memory + one wiped temp file.
#   2. The service ssh-agent (LocalSystem) REFUSES constrained adds --
#      `ssh-add -t`/`-c` both die with "agent refused operation" while a
#      plain add succeeds. Server-side expiry is therefore UNAVAILABLE:
#      the TTL is enforced CLIENT-side (connect treats an expired record
#      as uncovered and best-effort unloads it). Residual, stated
#      plainly: past expiry the key bytes stay usable in the agent until
#      the service restarts or the key is unloaded -- `agent unload`
#      (or a service restart) is the hard guarantee.
#   3. The rendered config's `IdentitiesOnly yes` suppresses agent
#      identities, so a loaded agent changes NOTHING until connect renders
#      the agent branch (pub-file selectors, no containers, no
#      dispatcher). Loading without the render branch would be a no-op.
#
# Security boundary (tell the user plainly, do not oversell):
#   - The agent pipe (\\.\pipe\openssh-ssh-agent) admits Authenticated
#     Users -- WEAKER than the vault's owner-only DACL. Any authenticated
#     local user can USE (not extract) cached keys for the TTL -- the
#     classic ssh-agent signature-oracle tradeoff. TTL default 8h.
#   - ForwardAgent is never enabled by the agent branch (jump chains use
#     ProxyCommand; the agent never leaves the local machine).
#   - FileZilla flows cannot use the agent (its SFTP engine needs PPK
#     files) and stored-secret (password) entries have no key to cache.

AGENT_DEFAULT_TTL = "8h"
AGENT_RECORD_VERSION = 1
_AGENT_TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_AGENT_TTL_RE = re.compile(r"^\s*(?:(\d+)\s*([smhdwSMHDW])\s*)+$|^\s*\d+\s*$")


def agent_record_path() -> Path:
    return AGENT_DIR / "keys.json"


def agent_pub_path(keyname: str) -> Path:
    return AGENT_DIR / f"{keyname}.pub"


def parse_agent_ttl(spec: str | None) -> tuple[int, str]:
    """`8h`/`90m`/seconds -> (seconds, canonical label). Dies on garbage."""
    if spec is None:
        spec = os.environ.get("WTSSH_AGENT_TTL") or AGENT_DEFAULT_TTL
    spec = spec.strip()
    if not _AGENT_TTL_RE.match(spec):
        die(f"bad agent TTL {spec!r}: seconds or a number with "
            f"s/m/h/d/w suffixes (e.g. 8h, 90m, 3600)")
    total = 0
    for num, unit in re.findall(r"(\d+)\s*([smhdwSMHDW]?)", spec):
        if not num:
            continue
        total += int(num) * _AGENT_TTL_UNITS.get(unit.lower(), 1)
    if total <= 0:
        die(f"bad agent TTL {spec!r}: must be positive")
    if total > 90 * 86400:
        # typo-level guard (F7): "9999w" would otherwise silently cache
        # near-forever. Reload to extend -- the window is always explicit.
        die(f"bad agent TTL {spec!r}: exceeds the 90d cap; pass a shorter "
            f"TTL and reload to extend it")
    return total, spec


def _run_ssh_add(argv: list[str]):
    """Seam for ssh-add: stdin is ALWAYS detached (it must never block on
    a console prompt -- every load path below is prompt-free by
    construction), output captured for diagnosis. Tests monkeypatch this."""
    return subprocess.run([resolve_bin("ssh-add")] + argv,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60)


def agent_list_live(strict: bool = True) -> tuple[str, dict[str, str]]:
    """Read-only agent inventory: ("ok"|"empty"|"no-agent", {fp: comment}).
    `ssh-add -l` exit codes: 0 keys listed, 1 no identities, 2 no agent
    connection. Never dies on a missing agent -- callers fall back to PIN.
    strict=False (the connect path) also swallows UNEXPECTED output into
    ("unknown", {}) instead of dying: a connect must always be able to
    fall back to the PIN path, never die on agent weirdness."""
    try:
        proc = _run_ssh_add(["-l"])
    except (OSError, subprocess.SubprocessError):
        if strict:
            raise
        return "unknown", {}
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode == 0:
        live: dict[str, str] = {}
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            # `<bits> <SHA256:...> <comment> (<type>)`
            if len(parts) >= 3 and parts[1].startswith("SHA256:"):
                live[parts[1]] = " ".join(parts[2:])
        return "ok", live
    if proc.returncode == 1 or "has no identities" in text:
        return "empty", {}
    if proc.returncode == 2 or "Could not open a connection" in text:
        return "no-agent", {}
    if not strict:
        return "unknown", {}
    die(f"ssh-add -l failed: {(proc.stderr or proc.stdout or 'unknown').strip()}")


def agent_fp_of_pub(pub_bytes: bytes) -> str:
    """The `ssh-add -l` fingerprint field for an OpenSSH pub line."""
    raw = base64.b64decode(pub_bytes.split()[1])
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def agent_key_material(keydata: bytes, pw: str) -> tuple[bytes, bytes]:
    """(pub_line, unencrypted_container) from vault key bytes + passphrase.
    Raises ValueError with a re-import hint when the format is foreign or
    the passphrase is wrong (cryptography raises ValueError -- and
    TypeError for a missing password on an encrypted key)."""
    from cryptography.hazmat.primitives import serialization as _ser
    password = pw.encode("utf-8") if pw else None
    priv = None
    try:
        try:
            priv = _ser.load_ssh_private_key(keydata, password=password)
        except ValueError:
            priv = _ser.load_pem_private_key(keydata, password=password)
    except (ValueError, TypeError) as e:
        raise ValueError(
            f"cannot unlock this key material ({e}); it may use a format "
            f"ssh cannot parse -- re-import it ('wtssh key remove <name>' + "
            f"'wtssh key import <name> <file>')") from e
    pub = (priv.public_key().public_bytes(
        _ser.Encoding.OpenSSH, _ser.PublicFormat.OpenSSH) + b"\n")
    try:
        # cryptography spells the OpenSSH container "PEM encoding +
        # OpenSSH format" (-----BEGIN OPENSSH PRIVATE KEY-----).
        clear = priv.private_bytes(_ser.Encoding.PEM,
                                   _ser.PrivateFormat.OpenSSH,
                                   _ser.NoEncryption())
    except ValueError:
        # No OpenSSH slot (DSA); PEM carries it and ssh-add reads both.
        clear = priv.private_bytes(_ser.Encoding.PEM,
                                   _ser.PrivateFormat.TraditionalOpenSSL,
                                   _ser.NoEncryption())
    return pub, clear


def agent_load_records() -> dict:
    """The cache index (public data only). Corrupt/missing -> {}: this is a
    hint file, never a reason to fail a connect."""
    try:
        obj = json.loads(agent_record_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(obj, dict) or obj.get("v") != AGENT_RECORD_VERSION:
        return {}
    keys = obj.get("keys")
    return keys if isinstance(keys, dict) else {}


def agent_save_records(records: dict) -> None:
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        apply_owner_only_dacl(AGENT_DIR)
    except DaclError:
        raise
    atomic_write_owner_only(
        agent_record_path(),
        json.dumps({"v": AGENT_RECORD_VERSION, "keys": records},
                   ensure_ascii=False, indent=2).encode("utf-8"))


def agent_cached_keys() -> list[str]:
    """Key names with a pub selector on disk (offline hint for print)."""
    return sorted(rec.get("key", name) for name, rec in
                  agent_load_records().items()
                  if agent_pub_path(name).exists())


def _record_expired(rec: dict, now: int) -> bool:
    """F2 semantics in one place: an unprovable TTL (missing/malformed
    expires_at) fails closed -- it counts as expired, never as
    "never expires". bool is an int subclass; True == 1 <= now, so a
    boolean expires_at also lands expired. Correct direction either way."""
    exp = rec.get("expires_at")
    return not isinstance(exp, int) or exp <= now


def agent_coverage(keys: list[str]) -> dict[str, str] | None:
    """{key: pubpath} when EVERY key is verifiably usable from the agent
    right now (unexpired record + fingerprint present in a live
    `ssh-add -l`), else None (caller falls back to the PIN path).
    Read-only, PIN-free -- except one best-effort cleanup: an EXPIRED but
    still-live key is `ssh-add -d`ed (our own tracked key only; failures
    swallowed) so expiry actually removes the credential instead of just
    ignoring it. The record/pub check runs FIRST so a machine with no
    cache never spawns a subprocess (keeps offline drills hermetic)."""
    if not keys:
        return None
    records = agent_load_records()
    now = int(time.time())
    wanted: dict[str, tuple[str, str]] = {}
    for key in keys:
        disk = disk_key_name(key)
        rec = records.get(disk)
        if not isinstance(rec, dict) or not isinstance(rec.get("fp"), str):
            return None
        # F2: a missing/malformed expires_at is NOT "never expires" -- an
        # unprovable TTL fails closed to the PIN path, like every other
        # uncertainty in this function (see _record_expired).
        if _record_expired(rec, now):
            _agent_try_unload(disk)
            return None
        pub = agent_pub_path(disk)
        if not pub.exists():
            return None
        wanted[key] = (rec["fp"], str(pub))
    state, live = agent_list_live(strict=False)
    if state != "ok":
        return None
    out: dict[str, str] = {}
    for key, (fp, pubpath) in wanted.items():
        if fp not in live:
            return None
        out[key] = pubpath
    return out


def _agent_try_unload(disk_keyname: str) -> None:
    """Best-effort `ssh-add -d` for one tracked pub selector. Never raises:
    expiry cleanup must not fail a connect that is already falling back
    to the PIN path."""
    try:
        pub = agent_pub_path(disk_keyname)
        if pub.exists():
            _run_ssh_add(["-d", str(pub)])
    except Exception:
        pass


def agent_wanted(args) -> bool:
    """Explicit opt-outs for the agent branch (--no-agent / WTSSH_NO_AGENT).
    --no-askpass does NOT opt out: the agent is ambient user session state,
    not wtssh automation, and the branch needs no dispatcher."""
    return not getattr(args, "no_agent", False) \
        and os.environ.get("WTSSH_NO_AGENT") != "1"


AUTO_AGENT_TTL_DEFAULT = "1h"


def _auto_agent_ttl() -> tuple[int, str]:
    """TTL for unwrap-triggered auto-staging. Defaults to 1h; WTSSH_AUTO_AGENT_TTL
    overrides (same syntax as `agent load --ttl`). Garbage fails OPEN to the
    default with a warning -- an auto-stage must never fail a connect."""
    spec = os.environ.get("WTSSH_AUTO_AGENT_TTL") or AUTO_AGENT_TTL_DEFAULT
    try:
        return parse_agent_ttl(spec)
    except SystemExit:
        print(f"wtssh: warning: bad WTSSH_AUTO_AGENT_TTL {spec!r}; "
              f"using {AUTO_AGENT_TTL_DEFAULT}", file=sys.stderr)
        return 3600, AUTO_AGENT_TTL_DEFAULT


def agent_stage_unlocked(unlocked: dict[str, tuple[bytes, str]],
                         *, source: str) -> list[str]:
    """Best-effort ssh-agent staging for already-unwrapped key material.

    Called on the connect/FileZilla PIN paths AFTER a successful unwrap, so the
    next connect can take the PIN-free agent branch. Never raises and never
    dies: any failure (agent down, bad material, DACL) is a stderr warning and
    the caller continues with its session containers. Records carry a 1h TTL
    (overridable via WTSSH_AUTO_AGENT_TTL); expiry stays wtssh-side enforced.
    """
    if not unlocked:
        return []
    staged: list[str] = []
    fresh: dict = {}
    try:
        ttl_secs, ttl_label = _auto_agent_ttl()
        for key, (keydata, pw) in unlocked.items():
            disk = disk_key_name(key)
            tmpdir: Path | None = None
            try:
                try:
                    pub, clear = agent_key_material(keydata, pw)
                except Exception as e:
                    print(f"wtssh: warning: auto-agent skipped key '{disk}': {e}",
                          file=sys.stderr)
                    continue
                try:
                    tmpdir, keyfile = secure_mkkey(clear, cleartext=True)
                except Exception as e:
                    print(f"wtssh: warning: auto-agent skipped key '{disk}': "
                          f"cannot stage container ({e})", file=sys.stderr)
                    continue
                try:
                    proc = _run_ssh_add([str(keyfile)])
                except (OSError, subprocess.SubprocessError) as e:
                    print(f"wtssh: warning: auto-agent skipped key '{disk}': "
                          f"ssh-add could not run ({e})", file=sys.stderr)
                    continue
                if proc.returncode != 0:
                    print(f"wtssh: warning: auto-agent skipped key '{disk}': "
                          f"ssh-add refused it: "
                          f"{(proc.stderr or proc.stdout or 'unknown').strip()}",
                          file=sys.stderr)
                    continue
                fp = agent_fp_of_pub(pub)
                _state, live = agent_list_live(strict=False)
                if fp not in live:
                    print(f"wtssh: warning: auto-agent skipped key '{disk}': "
                          f"fingerprint not listed after ssh-add", file=sys.stderr)
                    continue
                try:
                    AGENT_DIR.mkdir(parents=True, exist_ok=True)
                    pub_path = agent_pub_path(disk)
                    atomic_write(pub_path, pub + f"wtssh:{disk}\n".encode("ascii"))
                    try:
                        apply_owner_only_dacl(pub_path)
                    except DaclError:
                        print(f"wtssh: warning: owner-only DACL unavailable for "
                              f"{pub_path}; continuing (public key material)",
                              file=sys.stderr)
                except OSError as e:
                    print(f"wtssh: warning: auto-agent skipped key '{disk}': "
                          f"cannot persist selector ({e})", file=sys.stderr)
                    continue
                now = int(time.time())
                fresh[disk] = {"fp": fp, "ttl": ttl_secs,
                               "enforcement": "wtssh",
                               "loaded_at": now, "expires_at": now + ttl_secs}
                staged.append(disk)
                audit_log("verbose",
                          f"agent auto-staged key '{disk}' from {source} "
                          f"(ttl {ttl_label})")
            except (Exception, SystemExit) as e:
                # True best-effort floor: resolve_bin die() (SystemExit),
                # fingerprint/decode errors, or any unexpected failure on one
                # key must not kill the connect nor skip the remaining keys.
                # KeyboardInterrupt intentionally propagates (user abort).
                print(f"wtssh: warning: auto-agent skipped key '{disk}': "
                      f"{e}", file=sys.stderr)
                continue
            finally:
                wipe_session_dirs([tmpdir])
    except (Exception, SystemExit) as e:
        # Outermost floor: TTL parsing, index merge, or anything else above
        # must never take down the caller -- warn and keep partial progress.
        print(f"wtssh: warning: auto-agent staging from {source} aborted: "
              f"{e}", file=sys.stderr)
        return staged
    if fresh:
        try:
            merged = agent_load_records()
            merged.update(fresh)
            agent_save_records(merged)
        except DaclError as e:
            print(f"wtssh: warning: auto-agent staged {staged} but the cache "
                  f"index could not be protected ({e}); connects cannot use "
                  f"the agent branch until WTSSH_AGENT_DIR is on an "
                  f"ACL-capable volume", file=sys.stderr)
            return []
        except OSError as e:
            print(f"wtssh: warning: auto-agent staged {staged} but the cache "
                  f"index could not be saved ({e})", file=sys.stderr)
            return []
        print(f"wtssh: note: keys {', '.join(staged)} cached in ssh-agent "
              f"(ttl {ttl_label}) -- next connects skip the TPM PIN",
              file=sys.stderr)
    return staged


def action_agent_load(args):
    """One CNG PIN for the batch, then PIN-free connects until the TTL:
    unwrap -> cryptography re-serialize (unencrypted) -> owner-only temp ->
    `ssh-add` -> verify fingerprint live -> persist pub selector ->
    wipe temp. Per-key failures are collected, not fatal to the batch.

    The service agent refuses `ssh-add -t`, so the add is UNCONSTRAINED
    and the TTL is enforced client-side (agent_coverage + status read the
    record's expires_at). Said once per load on stderr, plainly."""
    ttl_secs, ttl_label = parse_agent_ttl(getattr(args, "ttl", None))
    if args.keys:
        targets = [disk_key_name(checked_key_name(k)) for k in args.keys]
    else:
        targets = (sorted(p.stem for p in KEYS_DIR.glob("*.wtv"))
                   if KEYS_DIR.exists() else [])
    if not targets:
        die("no vault keys to load ('wtssh key list' shows them)")
    missing = [k for k in targets if not vault_key_path(k).exists()]
    if missing:
        die(f"no vault key(s) named: {', '.join(missing)} "
            f"('wtssh key list' shows them)")
    # name/dest are re-purposed by the pin_agent_load template (it renders
    # {dest} as the TTL + {keys}); the batch still costs exactly one gesture.
    unlocked = _chain_unlock_keys(targets, "ssh-agent", ttl_label,
                                  ctx_msgid="pin_agent_load")
    loaded: list[str] = []
    failed: list[dict] = []
    fresh: dict = {}
    save_error: str | None = None
    try:
        for key in targets:
            tmpdir: Path | None = None
            try:
                keydata, pw = unlocked[key]
                try:
                    pub, clear = agent_key_material(keydata, pw)
                except Exception as e:
                    # per-key isolation (F1): one bad blob must not escape
                    # the batch -- BaseExceptions (Ctrl-C / SystemExit)
                    # still propagate. agent_key_material raises ValueError
                    # for bad material, but never trust a callee's
                    # exception contract for batch survival.
                    failed.append({"key": key, "reason": str(e)})
                    continue
                tmpdir, keyfile = secure_mkkey(clear, cleartext=True)
                try:
                    proc = _run_ssh_add([str(keyfile)])
                except (OSError, subprocess.SubprocessError) as e:
                    failed.append({
                        "key": key,
                        "reason": f"ssh-add could not run: {e}"})
                    continue
                if proc.returncode != 0:
                    failed.append({
                        "key": key, "reason": (
                            f"ssh-add refused it: "
                            f"{(proc.stderr or proc.stdout or 'unknown').strip()}")})
                    continue
                fp = agent_fp_of_pub(pub)
                _state, live = agent_list_live(strict=False)
                if fp not in live:
                    failed.append({
                        "key": key,
                        "reason": "ssh-add reported success but the "
                                  "fingerprint is not listed -- the agent may "
                                  "have restarted; retry the load"})
                    continue
                AGENT_DIR.mkdir(parents=True, exist_ok=True)
                pub_path = agent_pub_path(key)
                atomic_write(pub_path, pub + f"wtssh:{key}\n".encode("ascii"))
                try:
                    apply_owner_only_dacl(pub_path)
                except DaclError:
                    # selector is PUBLIC material; a loose ACL fails open
                    # safely -- keep it, warn once.
                    print(f"wtssh: warning: owner-only DACL unavailable for "
                          f"{pub_path}; continuing (public key material)",
                          file=sys.stderr)
                now = int(time.time())
                fresh[key] = {"fp": fp, "ttl": ttl_secs,
                              "enforcement": "wtssh",
                              "loaded_at": now, "expires_at": now + ttl_secs}
                loaded.append(key)
                audit_log("verbose",
                          f"agent loaded key '{key}' (ttl {ttl_label})")
            except Exception as e:
                # last-resort guard for the staging writes above
                # (secure_mkkey DaclError, atomic_write OSError, ...):
                # still per-key, still recorded, never an escape.
                failed.append({"key": key,
                               "reason": f"unexpected error: {e}"})
            finally:
                wipe_session_dirs([tmpdir])
    finally:
        # merge-on-save, even on Ctrl-C: keys already added MUST stay
        # tracked, or they linger in the agent unreachable by coverage
        # AND by default unload (F1). Re-reading narrows the race with a
        # concurrent `agent load` (we only add our own batch); a true
        # read-modify-write collision can still drop a batch -- which
        # only ever fails closed to the PIN path, never misuses a key.
        # On the exception path a save failure is recorded, not raised,
        # so the original propagates.
        if fresh:
            try:
                merged = agent_load_records()
                merged.update(fresh)
                agent_save_records(merged)
            except DaclError as e:
                save_error = str(e)
    if save_error is not None:
        die(f"agent load succeeded for {loaded}, but the cache index "
            f"could not be protected ({save_error}); connects cannot use "
            f"the agent branch until WTSSH_AGENT_DIR is on an ACL-capable "
            f"volume")
    print(json.dumps({"ok": not failed, "loaded": loaded,
                      "failed": failed, "ttl": ttl_label,
                      "enforcement": "wtssh"},
                     ensure_ascii=False))
    if loaded:
        # The one honest caveat, every load: the service agent takes no
        # `-t`, so expiry is wtssh-side (connect falls back to PIN and
        # unloads); key bytes linger in the agent until unload/reboot.
        print(f"wtssh: note: the Windows service agent ignores key "
              f"lifetimes, so the {ttl_label} TTL is enforced by wtssh "
              f"(connect falls back to PIN past expiry and unloads the "
              f"key) -- 'wtssh agent unload' removes it sooner",
              file=sys.stderr)
    if failed:
        sys.exit(1)


def action_agent_unload(args):
    """Drop wtssh-cached keys from the agent (`ssh-add -d` by pub selector).
    Defaults to keys WE track that are still live, PLUS tracked-but-expired
    ones (F6: expiry is exactly when removal matters most) -- never the
    user's hand-added keys. --all is the explicit `ssh-add -D` (also
    clears the user's own keys) plus our index."""
    records = agent_load_records()
    if getattr(args, "all", False):
        try:
            proc = _run_ssh_add(["-D"])
        except (OSError, subprocess.SubprocessError) as e:
            die(f"ssh-add -D could not run ({e}); the index was kept -- "
                f"retry when the agent is reachable")
        if proc.returncode != 0:
            die(f"ssh-add -D failed: "
                f"{(proc.stderr or proc.stdout or 'unknown').strip()}; "
                f"the index was kept -- retry when the agent is reachable")
        agent_save_records({})
        print(json.dumps({"ok": True, "unloaded": sorted(records),
                          "all": True}, ensure_ascii=False))
        return
    now = int(time.time())
    if args.keys:
        targets = [disk_key_name(checked_key_name(k)) for k in args.keys]
    else:
        # F3: non-strict -- an unreachable/weird agent must not die here;
        # say so and keep the records for a later retry.
        state, live = agent_list_live(strict=False)
        if state != "ok":
            print("wtssh: note: ssh-agent is unreachable; tracked records "
                  "are kept -- retry the unload when it is back",
                  file=sys.stderr)
        targets = [k for k, rec in records.items()
                   if isinstance(rec, dict)
                   and (rec.get("fp") in live or _record_expired(rec, now))]
    unloaded: list[str] = []
    failed: list[dict] = []
    for key in targets:
        pub = agent_pub_path(key)
        if key not in records and not pub.exists():
            failed.append({"key": key, "reason": "not tracked by wtssh"})
            continue
        if pub.exists():
            try:
                proc = _run_ssh_add(["-d", str(pub)])
            except (OSError, subprocess.SubprocessError) as e:
                failed.append({"key": key,
                               "reason": f"ssh-add could not run: {e}"})
                continue
            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout or "").strip()
                if "not found" not in err.lower() and \
                        "no such" not in err.lower():
                    failed.append({"key": key, "reason": err or "ssh-add -d failed"})
                    continue
        try:
            pub.unlink(missing_ok=True)
        except OSError:
            pass
        unloaded.append(key)
    # merge-on-save (same narrowed-window race as load, opposite
    # direction: drop only ours; a residual collision fails closed).
    merged = agent_load_records()
    for key in unloaded:
        merged.pop(key, None)
    agent_save_records(merged)
    print(json.dumps({"ok": not failed, "unloaded": unloaded,
                      "failed": failed}, ensure_ascii=False))
    if failed:
        sys.exit(1)


def action_agent_status(args):
    """Agent + cache inventory. Read-only, no PIN: live presence from
    `ssh-add -l`, TTL countdown from our index."""
    state, live = agent_list_live()
    records = agent_load_records()
    now = int(time.time())
    rows = []
    for key in sorted(records):
        rec = records[key]
        fp = rec.get("fp") if isinstance(rec, dict) else None
        exp = rec.get("expires_at") if isinstance(rec, dict) else None
        rows.append({
            "key": key, "fp": fp,
            "live": bool(fp) and fp in live,
            "pub": str(agent_pub_path(key)),
            "expires_at": exp,
            "expires_in": (exp - now) if isinstance(exp, int) else None,
            "expired": not isinstance(exp, int) or exp <= now,
        })
    out: dict = {"agent": state,
                 "defaultTtl": (os.environ.get("WTSSH_AGENT_TTL")
                                or AGENT_DEFAULT_TTL),
                 "keys": rows}
    if state == "no-agent":
        out["hint"] = ("ssh-agent is not reachable; start it once "
                       "('Start-Service ssh-agent', optionally "
                       "'Set-Service ssh-agent -StartupType Automatic') "
                       "and retry 'wtssh agent load'")
    print(json.dumps(out, ensure_ascii=False))


def action_secret_set(args):
    # interactive bits run BEFORE taking the lock: a slow passphrase entry
    # inside Lock() would blow past its 60s staleness deadline and let a
    # second writer steal the lock (lost update).
    profile = require_profile(load(), args.name)  # entry must exist
    if not cmd_name_is_safe(args.name):
        # refuse BEFORE secret_store writes a blob that the routed rewrite
        # would then refuse to reference (the blob would be an orphan)
        die(f"entry '{args.name}' cannot take a stored passphrase: its name "
            f"contains cmd metacharacters and the routed tab would run them "
            f"via cmd.exe -- rename it first: wtssh rename '{args.name}' "
            f"<safe-name>")
    bad = cmd_risky_payload_chars(plain_line_lenient(profile))
    if bad:
        die(f"entry '{args.name}' cannot take a stored passphrase: its ssh "
            f"command carries cmd metacharacters "
            f"{' '.join(repr(c) for c in bad)} and the routed tab would run "
            f"them via cmd.exe -- remove them first (host/user/options/"
            f"remote command)")
    if profile_key_refs(profile) or has_lexical_key_ref(plain_line_lenient(profile)):
        die(f"entry '{args.name}' references a vault key; that key's "
            f"passphrase lives inside its blob. Drop the reference first "
            f"('wtssh edit {args.name} --key none', or 'wtssh key remove "
            f"--force <key>') if you want a plain stored passphrase")
    collide = secret_case_collision(args.name)
    if collide:
        # placed BEFORE the vault/prompt paths: a bare collision must not
        # cost a PIN window or a dialog round-trip
        die(f"a stored-passphrase blob for '{collide}' already exists and "
            f"Windows file names are case-insensitive: storing '{args.name}' "
            f"would overwrite it and that entry would then fail the blob "
            f"ownership check at connect. Remove the other blob first "
            f"('wtssh secret remove {collide}') or pick another name")
    if not vault_exists():
        die("vault is not initialized; run 'wtssh vault init' first", 4)
    if sys.stdin is not None and sys.stdin.isatty():
        pw = read_passphrase(f"passphrase for '{args.name}': ")
    else:
        # agent-driven session: stdin is an LLM-visible pipe -- capture the
        # passphrase in a native dialog instead; plaintext never crosses it
        pw = gui_passphrase("wtssh secret set", args.name)
    if not pw:
        die("empty passphrase; nothing stored")
    with Lock():
        data = load()
        p = require_profile(data, args.name)
        blob = secret_path(args.name)
        prev_blob = blob.read_bytes() if blob.exists() else None
        try:
            secret_store(args.name, pw)
            ensure_shim()      # routed lines point at it, so it must exist
            p["commandline"] = routed_line(args.name, p)
            save(data)
        except BaseException:
            # same discipline as rename/key import's drop_blobs: a refused
            # routed rewrite or a failed save must not leave a new blob --
            # or a clobbered predecessor -- behind. Rollback failure must
            # not mask the original error, only add to it.
            try:
                if prev_blob is None:
                    blob.unlink(missing_ok=True)
                else:
                    atomic_write(blob, prev_blob)
            except OSError as rb_err:
                print(f"wtssh: warning: rollback of secret blob {blob} "
                      f"failed: {rb_err} -- remove it manually",
                      file=sys.stderr)
            raise
    print(json.dumps({"ok": True, "stored": args.name}))


def action_secret_remove(args):
    p = secret_path(args.name)
    if not p.exists():
        die(f"no stored passphrase for '{args.name}'")
    with Lock():
        data = load()
        prof = find_profile(data, args.name)
        if prof is not None:
            line = plain_line_lenient(prof)
            if entry_key_refs(line):
                # the removed passphrase was the only reason to route this
                # entry, but it still references a vault key -- de-routing
                # would leave a bare `-i wtv:<name>` that ssh reads as a
                # filename, so keep the shim
                ensure_shim()
                prof["commandline"] = routed_line(args.name,
                                                  {"commandline": line})
            else:
                prof["commandline"] = line
            save(data)
        # the blob goes away only after the settings write succeeded: a
        # refused routed rewrite (cmd-unsafe legacy name) or a failed save
        # must not leave a routed line whose secret is already gone.
        try:
            p.unlink()
        except OSError as e:
            print(f"wtssh: warning: could not remove blob {p}: {e} -- "
                  f"remove it manually", file=sys.stderr)
    print(json.dumps({"ok": True, "removed": args.name}))


def action_secret_list(args):
    names = sorted(p.stem for p in SECRETS_DIR.glob("*.bin")) if SECRETS_DIR.exists() else []
    print(json.dumps(names, ensure_ascii=False))


def action_vault_init(args):
    """Create the TPM vault key. Two dialogs: PIN selection at finalize,
    then a consent-protected wrap+unwrap self-test."""
    # Under the same lock as every other vault mutation: a concurrent key
    # import sealing blobs while init recreates the vault key would leave
    # them permanently undecryptable.
    with Lock():
        if vault_exists():
            die("a vault key already exists; re-initializing would destroy "
                "it and every sealed blob. Run 'wtssh vault remove' first "
                "(after removing imported keys)", 4)
        proc = vault_run("init")
        if proc.returncode == 5:
            die(f"vault init refused: "
                f"{(proc.stderr or 'guard tripped').strip()}", 4)
        if proc.returncode != 0:
            die(f"vault init failed: "
                f"{(proc.stderr or 'unknown').strip()}", 4)
        meta = {"keyName": VAULT_KEY, "alg": "RSA-OAEP-SHA256 + AES-256-GCM",
                "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        atomic_write(vault_meta_path(),
                     json.dumps(meta, ensure_ascii=False).encode("utf-8"))
    print(json.dumps({"ok": True, **meta}, ensure_ascii=False))


def action_vault_status(args):
    exists = vault_exists()
    meta = None
    if vault_meta_path().exists():
        try:
            meta = json.loads(vault_meta_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = None
    keys = sorted(p.name for p in KEYS_DIR.glob("*.wtv")) if KEYS_DIR.exists() else []
    secrets = sorted(p.stem for p in SECRETS_DIR.glob("*.bin")) if SECRETS_DIR.exists() else []
    print(json.dumps({"initialized": exists, "meta": meta,
                      "vaultKeys": keys, "passphraseSecrets": secrets},
                     ensure_ascii=False))


def action_vault_remove(args):
    """Delete the TPM vault key. Sealed blobs become undecryptable; warn."""
    # Drill-env guard, FIRST: WTSSH_KEYS/WTSSH_SECRETS point every
    # blob-existence check (the two below AND the one inside cng-vault.ps1)
    # at sandbox dirs, so under them both guards pass while the real blobs
    # stay sealed elsewhere -- deleting the real TPM key would make those
    # permanently undecryptable. The overrides are drill/test hooks; refuse.
    if os.environ.get("WTSSH_KEYS") or os.environ.get("WTSSH_SECRETS"):
        die("WTSSH_KEYS/WTSSH_SECRETS are set (drill mode); 'vault remove' "
            "would delete the REAL TPM vault key while the real blobs stay "
            "sealed elsewhere. Unset both overrides and retry.", 4)
    with Lock():  # no key import may seal blobs while the vault key dies
        if KEYS_DIR.exists() and any(KEYS_DIR.glob("*.wtv")):
            die("standalone vault keys still exist; remove them first "
                "('wtssh key list', then 'wtssh key remove NAME' -- entries "
                "still referencing one need 'wtssh edit NAME --key ...' or "
                "'wtssh key remove --force NAME') -- deleting the vault key "
                "would make their blobs permanently undecryptable", 4)
        if SECRETS_DIR.exists() and any(SECRETS_DIR.glob("*.bin")):
            die("stored passphrase secrets still exist; remove them first "
                "('wtssh secret remove NAME') -- deleting the vault key "
                "would make their blobs permanently undecryptable", 4)
        proc = vault_run("remove")
        if proc.returncode == 2:
            die("no vault key to remove")
        if proc.returncode == 5:
            die(f"vault remove refused: "
                f"{(proc.stderr or 'guard tripped').strip()}", 4)
        if proc.returncode != 0:
            die(f"vault remove failed: "
                f"{(proc.stderr or 'unknown').strip()}", 4)
        vault_meta_path().unlink(missing_ok=True)
    print(json.dumps({"ok": True}))


# ------------------------------------------------------------------ connect

# ------------------------------------------------- jump chain dispatch
# A jump chain whose every link is a book entry is RENDERED at connect time
# into a temporary -F config -- opaque block names (C3), an explicit quoted
# ProxyCommand chain, one IdentityFile per hop -- and the whole ssh process
# tree gets exactly one askpass: a dispatcher that hands each container its
# own passphrase by matching the "passphrase for key '<path>'" prompt.
# Chains that cannot be rendered keep
# the standard -J behavior verbatim (plan reason recorded, never silent).

_ASKPASS_SUPPORT: tuple[bool, str] | None = None


def ssh_askpass_support() -> tuple[bool, str]:
    """Does this machine's ssh understand SSH_ASKPASS_REQUIRE? The option
    appeared in OpenSSH 8.4; older ssh silently ignores it and asks for the
    passphrase ON THE TTY -- the connect flow must warn, because 'the tab
    never shows a passphrase prompt' quietly stops being true. Fail-open
    (with a note) when the probe itself fails: a broken probe must not block
    connecting. Memoized per process (doctor calls it per entry)."""
    global _ASKPASS_SUPPORT
    if _ASKPASS_SUPPORT is not None:
        return _ASKPASS_SUPPORT
    ssh_exe = find_bin("ssh")
    if ssh_exe is None:
        _ASKPASS_SUPPORT = (True, "ssh not found on PATH")
        return _ASKPASS_SUPPORT
    try:
        r = subprocess.run([ssh_exe, "-V"], capture_output=True, text=True,
                           timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        _ASKPASS_SUPPORT = (True, f"version probe failed ({e})")
        return _ASKPASS_SUPPORT
    # Windows OpenSSH reports 'OpenSSH_for_Windows_9.5p2'; upstream reports
    # 'OpenSSH_9.5p2' -- accept both.
    m = re.search(r"OpenSSH(?:_for_Windows)?[_-](\d+)\.(\d+)",
                  (r.stderr or "") + (r.stdout or ""))
    if not m:
        _ASKPASS_SUPPORT = (True, "unrecognized ssh version string")
        return _ASKPASS_SUPPORT
    ver = (int(m.group(1)), int(m.group(2)))
    _ASKPASS_SUPPORT = (ver >= (8, 4), f"OpenSSH {ver[0]}.{ver[1]}")
    return _ASKPASS_SUPPORT


def run_root() -> Path:
    """Root of rendered-session dirs (temp -F config, askpass map). Under
    %LOCALAPPDATA%\\wtssh (user-profile ACLs) rather than %TEMP%; the
    owner-only DACL is applied on top anyway."""
    return Path(os.environ.get("WTSSH_RUN_DIR")
                or (LOCALAPPDATA / "wtssh" / "run"))


def askpass_dispatcher_path() -> Path:
    return Path(os.environ.get("WTSSH_SHIM_DIR",
                               LOCALAPPDATA / "wtssh")) / "wtssh-askpass.cmd"


def ensure_askpass_dispatcher() -> Path:
    """(Re)write the dispatcher launcher when its content drifted -- same
    discipline as ensure_shim: a stable .cmd path survives interpreter
    moves, and every dispatching connect re-points it at the running python."""
    dp = askpass_dispatcher_path()
    body = ("@echo off\r\n"
            f'"{sys.executable}" "{SCRIPTS / "wtssh.py"}" __askpass %*\r\n'
            ).encode("utf-8")
    if not dp.exists() or dp.read_bytes() != body:
        dp.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(dp, body)
    return dp


def make_run_dir(prefix: str = RUN_DIR_PREFIX) -> Path:
    """One session dir under run_root() (temp -F config, askpass map):
    mkdtemp, owner-only DACL, owner.pid marker for the orphan sweeper
    (pid liveness check; marker-less dirs only go after max_age). The
    FileZilla tunnel passes RUN_DIR_PREFIX + "fz-" so fz_sync_server can
    recognize wiped session keyfiles by the prefix."""
    run_root().mkdir(parents=True, exist_ok=True)
    rundir = Path(tempfile.mkdtemp(prefix=prefix,
                                   dir=str(run_root())))
    try:
        apply_owner_only_dacl(rundir)
    except BaseException:
        # fail-closed means no stranded half-protected dir: remove the
        # partial dir ourselves (best-effort -- the orphan sweeper is the
        # belt) before the error surfaces
        shutil.rmtree(rundir, ignore_errors=True)
        raise
    try:
        (rundir / "owner.pid").write_text(str(os.getpid()),
                                          encoding="ascii")
    except OSError:
        pass  # sweeper falls back to the age-only rule for this dir
    return rundir


def dispatch_env(map_path: Path) -> dict:
    """Child env for a dispatching ssh run (rendered and legacy paths
    alike): the askpass dispatcher plus the owner-only map path. The
    passphrase itself NEVER rides the environment; a stale
    WTSSH_PASSPHRASE from an older session is stripped defensively."""
    env = dict(os.environ)
    env.pop("WTSSH_PASSPHRASE", None)
    env["SSH_ASKPASS"] = str(ensure_askpass_dispatcher())
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["WTSSH_ASKPASS_MAP"] = str(map_path)
    env["DISPLAY"] = env.get("DISPLAY", ":0")
    return env


def write_askpass_map(map_path: Path, keys: dict,
                      login: dict | None) -> None:
    """Schema v2 askpass map (strict -- MAP_SCHEMA_VERSION): `keys` maps
    truncated container paths to one-shot entries, `login` is the
    stored-secret slot ({"pw", "uses", "identities"}) or None. Owner-only
    DACL BEFORE the bytes land -- the map is a secret carrier. The
    dispatcher refuses any file without the v2 marker: no legacy shapes
    exist and none are tolerated."""
    payload = {"v": MAP_SCHEMA_VERSION, "keys": keys, "login": login}
    secure_write(map_path,
                 json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def audit_log(level: str, msg: str) -> None:
    """Best-effort audit. Default records misses/failures
    only; WTSSH_AUDIT=verbose also records hits and render summaries. A log
    write must never fail a connection (and the path is overridable so
    drills do not touch the real log)."""
    if level != "warn" and os.environ.get("WTSSH_AUDIT") != "verbose":
        return
    try:
        d = Path(os.environ.get("WTSSH_AUDIT_DIR")
                 or (LOCALAPPDATA / "wtssh" / "log"))
        d.mkdir(parents=True, exist_ok=True)
        f = d / f"render-{time.strftime('%Y%m%d')}.log"
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} [{level}] {msg}\n")
    except OSError:
        pass


class _AskMiss(Exception):
    """The dispatcher cannot (or must not) answer this prompt."""


def entry_ssh_argv(p: dict) -> list[str]:
    """The shunquoted ssh tokens of any profile (ssh_argv without the
    'must be ssh' gate, so plan paths can inspect entries it will never
    execute)."""
    toks = strict_tokens_or_die(p, p.get("commandline") or "")
    if is_routed(toks):
        toks = toks[toks.index("--") + 1:]
    return [shunquote(t) for t in toks]


def argv_identity_files(toks: list[str]) -> list[str]:
    """Every -i value in the option region. argv_key_refs' sibling: that one
    answers 'which vault keys does this argv reference' (wtv: only), this
    one answers 'which identities does it carry at all' -- plain file paths
    included, because a rendered hop block must transcribe them all."""
    out: list[str] = []
    i = 1
    while i < len(toks):
        t = toks[i]
        if not t.startswith("-"):
            break  # the destination; everything after is a remote command
        if t in VALUE_OPTS and i + 1 < len(toks):
            if t == "-i":
                out.append(toks[i + 1])
            i += 2  # option + value, then keep scanning
            continue
        i += 1  # boolean flag; attached-value forms ride in extra
    return out


def identity_list(idents: list[str]) -> list[dict]:
    """Classify -i values for the plan: keyref (vault, unwrapped at
    materialize) or file (used verbatim, quoted)."""
    out = []
    for v in idents:
        ref = resolve_key_ref(v)
        if ref is not None:
            out.append({"kind": "keyref", "key": ref[1]})
        else:
            out.append({"kind": "file", "path": v})
    return out


def _hop_specs(jump: str | None) -> list[str]:
    return [s.strip() for s in (jump or "").split(",") if s.strip()]


def flatten_chain(data: dict, jump: str | None) -> tuple[list[dict], str | None]:
    """The full chain as book entries, outermost first: the -J comma order,
    with each hop's own --jump resolved BEFORE it (a hop entered through its
    own jump is reached later, so its upstreams precede it). (hops, reason):
    a non-None reason means the chain cannot be rendered; hops holds what
    was collected up to that point, for diagnostics only."""
    hops: list[dict] = []
    seen: set[str] = set()

    def visit(specs: list[str], on_path: frozenset[str]) -> str | None:
        for spec in specs:
            if spec in on_path:
                # re-encountered while still an ANCESTOR of the current node:
                # a genuine cycle (a -> b -> a)
                return f"jump chain cycle through {spec!r}"
            if spec in seen:
                # already materialized elsewhere in this chain -- e.g.
                # `-J B,C` where C itself carries `--jump B`: that block IS
                # this node (B is reached once, as the outer hop), so
                # skipping is faithful, not a cycle
                continue
            seen.add(spec)
            jp = find_profile(data, spec)
            if jp is None:
                return (f"hop {spec!r} is not a book entry -- its identity "
                        f"would come from the user config, which a rendered "
                        f"-F config replaces")
            try:
                f = cmd_fields(jp)
            except SystemExit:
                return (f"hop entry {spec!r} has an unparsable commandline "
                        f"({_LAST_DIE})")
            up = _hop_specs(f["jump"])
            if up:
                reason = visit(up, on_path | {spec})  # upstreams land first
                if reason:
                    return reason
            hops.append({"spec": spec, "profile": jp, "fields": f})
        return None

    reason = visit(_hop_specs(jump), frozenset())
    return hops, reason


def _cfg_safe(value: str | None) -> bool:
    """A rendered config VALUE position: embedded quotes would break the
    double-quoted ssh_config value, control characters would forge lines.
    None means the field is absent -- absent is safe."""
    if value is None:
        return True
    return '"' not in value and all(ord(c) >= 32 for c in value)


def rebuild_target_argv(argv: list[str], config_path: str,
                        dest_block: str = BLOCK_TARGET) -> list[str] | None:
    """argv for the rendered run: drop -i pairs (identities live in the
    target block) and the -J pair (the chain lives in the config); every
    other token survives in order; the destination becomes the opaque block
    name (BLOCK_TARGET for connects; the FileZilla SOCKS tunnel passes the
    LAST HOP's block, whose namespace is where the dials must originate).
    None → not renderable, keep the stored argv (-J path)."""
    out: list[str] = [argv[0], "-F", config_path]
    dest_seen = False
    i = 1
    while i < len(argv):
        t = argv[i]
        if dest_seen:
            out.append(t)  # remote command keeps its own flags (cmd_fields rule)
            i += 1
            continue
        if t in ("-i", "-J") and i + 1 < len(argv):
            i += 2  # both moved into the rendered config
            continue
        if t == "-F":
            return None  # the entry carries its own config; do not guess
        if t in VALUE_OPTS and i + 1 < len(argv):
            out += [t, argv[i + 1]]
            i += 2
            continue
        if t.startswith("-") and len(t) > 1:
            if t.startswith("-J"):
                return None  # attached -J spec: ssh would ALSO proxy (F9 class)
            out.append(t)
            i += 1
            continue
        out.append(dest_block)
        dest_seen = True
        i += 1
    return out if dest_seen else None


def build_render_plan(data: dict, p: dict, fields: dict,
                      argv: list[str],
                      dispatch_active: bool = True) -> tuple[dict | None, str | None]:
    """(plan, reason). plan != None → the chain is fully renderable;
    reason != None → keep the standard -J path verbatim, with the reason
    recorded. Pure book-entry reading: no user-config probes, no vault, no
    secrets -- print --plan and doctor share this and must stay offline.
    One deliberate die(): a hop authenticating with a STORED
    PASSPHRASE while THIS connect will actively dispatch vault key
    passphrases (dispatch_active and the entry carries vault refs) -- the
    dispatcher only answers key passphrases, so that hop can never
    authenticate no matter which path runs; a loud refusal beats a
    hopeless connect. When dispatch is off (--no-askpass) or the entry
    has no vault keys, the fallback runs ssh with NO askpass env (fully
    interactive -- the user types the hop's password in the terminal,
    exactly like the plain path), so those cases only fall back, never
    die."""
    vault_refs = argv_key_refs(argv)
    dispatching = dispatch_active and bool(vault_refs)
    hops: list[dict] = []
    if fields["jump"]:
        if secret_path(p["name"][len(PREFIX):]).exists():
            return None, ("entry has a stored passphrase; the -J path "
                          "dispatches it for the target login")
        hops, reason = flatten_chain(data, fields["jump"])
        if reason:
            return None, reason
    else:
        # no chain: render only when the entry itself carries multiple
        # DISTINCT vault keys -- the dispatcher serves that honestly, where
        # the legacy path had to fail closed (one session passphrase)
        distinct = {i["key"] for i in identity_list(argv_identity_files(argv))
                    if i["kind"] == "keyref"}
        if len(distinct) < 2:
            return None, None
    blocks: list[dict] = []
    for pos, hop in enumerate(hops, 1):
        f = hop["fields"]
        hname = hop["profile"]["name"][len(PREFIX):]
        if not f["host"]:
            return None, f"hop entry {hop['spec']!r} has no parsable host"
        if secret_path(hname).exists():
            if dispatching:
                die(f"hop '{hop['spec']}' authenticates with a stored "
                    f"passphrase (password auth) while this connect "
                    f"dispatches vault key passphrases -- the dispatcher "
                    f"cannot serve that hop's password prompt, so the hop "
                    f"can never authenticate on either path; "
                    f"import its credential as a vault key ('wtssh key "
                    f"import'), connect with --no-askpass to stay fully "
                    f"interactive, or connect the hop directly", 4)
            return None, (f"hop '{hop['spec']}' holds a stored passphrase "
                          f"(password auth); the -J path stays fully "
                          f"interactive for it -- you will type the hop "
                          f"password in the terminal")
        if f["extra"] or f["tail"]:
            return None, (f"hop entry {hop['spec']!r} carries extra ssh "
                          f"options the renderer does not model; keeping the "
                          f"-J path (which never applied them to the hop "
                          f"either)")
        for v in (f["user"], f["host"], f["port"]):
            if not _cfg_safe(v):
                return None, (f"hop entry {hop['spec']!r} has a value that "
                              f"cannot ride a rendered config block")
        try:
            hadent = identity_list(argv_identity_files(entry_ssh_argv(
                hop["profile"])))
        except SystemExit:
            return None, (f"hop entry {hop['spec']!r} has an unparsable "
                          f"commandline ({_LAST_DIE})")
        for ident in hadent:
            if ident["kind"] == "file" and not _cfg_safe(ident["path"]):
                return None, (f"hop entry {hop['spec']!r} has a key path "
                              f"that cannot ride a rendered config block")
        blocks.append({"block": f"wtssh-hop-{pos}", "entry": hop["spec"],
                       "name": hname, "user": f["user"], "host": f["host"],
                       "port": f["port"], "identities": hadent})
    tidents = identity_list(argv_identity_files(argv))
    for v in (fields["user"], fields["host"], fields["port"]):
        if not _cfg_safe(v):
            return None, "entry has a value that cannot ride a config block"
    for ident in tidents:
        if ident["kind"] == "file" and not _cfg_safe(ident["path"]):
            return None, "entry has a key path that cannot ride a config block"
    blocks.append({"block": BLOCK_TARGET, "entry": p["name"][len(PREFIX):],
                   "name": p["name"][len(PREFIX):], "user": fields["user"],
                   "host": fields["host"], "port": fields["port"],
                   "identities": tidents})
    new_argv = rebuild_target_argv(argv, "<config>")
    if new_argv is None:
        return None, ("the stored commandline mixes forms the renderer does "
                      "not model (attached -J, own -F, or no destination)")
    keys: list[str] = []
    for b in blocks:
        for ident in b["identities"]:
            if ident["kind"] == "keyref" and ident["key"] not in keys:
                keys.append(ident["key"])
    return {"blocks": blocks, "keys": keys, "argv": argv}, None


def render_plan_safe(data: dict, p: dict) -> tuple[dict | None, str | None]:
    """build_render_plan for read paths (print/doctor): never dies, never
    touches the vault; a poisoned commandline or a refused hop degrades to
    (None, reason)."""
    try:
        f = cmd_fields(p)
        argv = entry_ssh_argv(p)
    except SystemExit:
        return None, _LAST_DIE or "commandline cannot be parsed"
    try:
        return build_render_plan(data, p, f, argv)
    except SystemExit:
        return None, _LAST_DIE or "chain cannot be rendered"


def plan_public(plan: dict | None, reason: str | None) -> dict:
    """The secret-free render summary for print --plan / doctor.
    `agentCached` is an offline hint only (pub selectors on disk -- which
    keys `agent load` has staged); connect re-verifies liveness by
    fingerprint at run time, so this never promises a PIN-free connect."""
    if plan is None:
        return {"mode": "legacy", "reason": reason, "pinPrompts": 0,
                "keys": 0, "blocks": None, "agentCached": []}
    cached = set(agent_cached_keys())
    return {"mode": "dispatch" if plan["keys"] else "render",
            "reason": None,
            # batch unwrap: one CNG consent gesture covers the whole chain
            # (PCP does not re-prompt within a key handle)
            "pinPrompts": 1 if plan["keys"] else 0,
            "keys": len(plan["keys"]),
            "agentCached": sorted(k for k in plan["keys"] if k in cached),
            "blocks": [{"block": b["block"], "entry": b["entry"],
                        "user": b["user"], "host": b["host"],
                        "port": b["port"], "identities": b["identities"]}
                       for b in plan["blocks"]]}


def render_config(blocks: list[dict], containers: dict[str, str],
                  config_path: str, ssh_exe: str, dispatch: bool,
                  probe: bool = False) -> str:
    """The temporary -F file. Outermost hop first, no
    ProxyCommand on it; hop-i proxies through hop-(i-1); the target proxies
    through the last hop. Every path double-quoted (F6 -- the only necessary
    mechanism); %h:%p expands per owning block. IdentitiesOnly yes
    trims agent-supplied identities (F7a: it cannot and does not silence
    the block's own IdentityFile lines). probe=True additionally writes a
    ConnectTimeout into every block: it is only ever used by probe_chain's
    config variant, where the INNER (ProxyCommand) sshs read it -- a
    command-line -o cannot reach them (F2), and the outer probe process
    must NOT carry a tight timeout of its own (its banner wait includes
    the time the user spends at the inner tunnel's passphrase prompt)."""
    def q(v: str) -> str:
        return '"' + v + '"'

    lines = ["# generated by wtssh -- rendered jump chain; do not edit"]
    for idx, b in enumerate(blocks):
        lines += ["", f"Host {b['block']}", f"    HostName {b['host']}"]
        if b["user"]:
            lines.append(f"    User {b['user']}")
        if b["port"]:
            lines.append(f"    Port {b['port']}")
        for ident in b["identities"]:
            if ident["kind"] == "keyref":
                lines.append(f"    IdentityFile {q(containers[ident['key']])}")
            else:
                lines.append(f"    IdentityFile {q(ident['path'])}")
        lines.append("    IdentitiesOnly yes")
        if probe:
            lines.append("    ConnectTimeout 15")
        if dispatch:
            # with SSH_ASKPASS_REQUIRE=force nothing can answer a password
            # prompt; declare it so the hop fails fast instead of empty-
            # retrying (same hardening the legacy path inserts into argv)
            lines += ["    PasswordAuthentication no",
                      "    ChallengeResponseAuthentication no"]
        if idx > 0:
            lines.append(f"    ProxyCommand {q(ssh_exe)} -F {q(config_path)}"
                         f' -W "%h:%p" {blocks[idx - 1]["block"]}')
    return "\n".join(lines) + "\n"


def secure_write(path: Path, payload: bytes) -> None:
    """Owner-only DACL BEFORE the bytes land -- for files carrying secrets
    (the askpass map), mirroring secure_mkkey's ordering."""
    path.touch()
    apply_owner_only_dacl(path)
    with open(path, "wb") as f:
        f.write(payload)


class DaclError(OSError):
    """The owner-only DACL could not be applied -- the fail-closed carrier.
    Subclasses OSError so existing `except OSError` sites keep working,
    while main() converts it into a clean remediation message instead of
    a bare traceback. Raised by the ctypes DACL path (apply_owner_only_dacl)
    whenever a secret file cannot be protected: callers either die on it
    (fail-closed sites) or warn (the askpass-map save, where ssh is already
    waiting for an answer)."""


def atomic_write_owner_only(path: Path, payload: bytes) -> None:
    """atomic_write for a secret carrier: the TEMP file gets the owner-only
    DACL before any content exists, then os.replace lands it. A plain
    atomic_write would hand the replaced file the token's default ACL (the
    run dir's PROTECTED DACL uses AddAccessAllowedAce without inheritance,
    so children do NOT inherit it) -- after the first dispatch the map
    would silently degrade to user+SYSTEM+Administrators readability.
    Any failure -- a DACL error included -- unlinks the still-empty temp
    before propagating: no .wtssh.*.tmp litter in a caller-chosen target
    directory."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".wtssh.",
                               suffix=".tmp")
    os.close(fd)
    try:
        apply_owner_only_dacl(Path(tmp))
        with open(tmp, "wb") as f:
            f.write(payload)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_KNOWN_HOSTS_CACHE: dict[tuple[str, str | None], list[Path]] = {}


def _known_hosts_files(host: str, port: str | None) -> list[Path]:
    """The effective known_hosts files for a destination, resolved OFFLINE
    via `ssh -G` (no connection; the values carry the user's
    UserKnownHostsFile/GlobalKnownHostsFile, which a bare `ssh-keygen -F`
    would ignore). Tokens like __PROGRAMDATA__ are expanded;
    unparseable output falls back to the two default user files. Runs the
    user's `Match exec` blocks if any (F11, documented). Cached per
    destination for the connect's lifetime."""
    key = (host, port)
    if key in _KNOWN_HOSTS_CACHE:
        return _KNOWN_HOSTS_CACHE[key]
    files: list[Path] = []
    ssh_exe = find_bin("ssh")
    if ssh_exe is not None:
        try:
            cmd = [ssh_exe, "-G"]
            if port:
                cmd += ["-p", str(port)]
            cmd.append(host)
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15)
            if r.returncode == 0:
                for line in (r.stdout or "").splitlines():
                    kw, _, val = line.partition(" ")
                    if kw in ("userknownhostsfile", "globalknownhostsfile"):
                        for tok in val.split():
                            files.append(Path(tok.replace(
                                "__PROGRAMDATA__",
                                os.environ.get("PROGRAMDATA", ""))))
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not files:
        ssh_dir = Path.home() / ".ssh"
        files = [ssh_dir / "known_hosts", ssh_dir / "known_hosts2"]
    _KNOWN_HOSTS_CACHE[key] = files
    return files


def _host_key_known(host: str, port: str | None) -> bool:
    """known_hosts coverage check honoring the user's effective
    known_hosts files. Best-effort: unreadable files are skipped."""
    keygen = find_bin("ssh-keygen")
    if not keygen:
        return False
    lookup = f"[{host}]:{port}" if port else host
    for f in _known_hosts_files(host, port):
        try:
            r = subprocess.run([keygen, "-F", lookup, "-f", str(f)],
                               capture_output=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    return False


# Auth-none host-key probes intentionally reach the auth stage with no
# credentials. OpenSSH then prints e.g. `user@10.0.0.1: Permission denied
# (publickey,...)` using the local Windows username -- that looks like a
# failed real login. Filter ONLY those lines; keep fingerprints, yes/no
# prompts, warnings, and transport errors.
# Optional `user@host: ` prefix: username may be empty when a 256-byte chunk
# boundary already flushed it. Host may contain IPv6 colons / brackets; the
# message separator is the final `:\s+` (colon + whitespace -- OpenSSH's
# `user@host: message` shape). Using `\s*` would let IPv6 `::` look like a
# separator and flush `user@2001:db8::1` early. Lines like
# `ssh: /path/known_hosts: Permission denied` have no `@` and do not start
# with the message -- they are kept.
_HOSTKEY_PROBE_AUTH_NOISE_RE = re.compile(
    r"(?i)^(?:[^@\s]*@.+:\s+)?"
    r"(?:Permission denied\b.*|Authentications that can continue:.*)$"
)
_HOSTKEY_PROBE_AUTH_NOISE_TARGETS = (
    "Permission denied",
    "Authentications that can continue",
)


def _is_hostkey_probe_auth_noise(line: str) -> bool:
    """True for a complete (or newline-stripped) auth-none failure line."""
    return bool(_HOSTKEY_PROBE_AUTH_NOISE_RE.match(
        line.replace("\r", "").rstrip("\n")))


def _could_be_hostkey_probe_auth_noise_prefix(partial: str) -> bool:
    """True if an incomplete stderr fragment might still become auth noise.

    Incomplete non-noise (especially the host-key `Are you sure...?` prompt,
    which has no trailing newline) must return False so it is flushed live.
    Token-like prefixes without `@`/spaces (e.g. a split `user` before
    `@10.0.0.1: Permission denied`) are held so chunk boundaries cannot
    orphan the username and defeat the noise matcher. After `@`, hold through
    IPv6 colons until the message side disambiguates.
    """
    s = partial.replace("\r", "")
    if not s:
        return False
    if _is_hostkey_probe_auth_noise(s):
        return True
    lower = s.lower()
    for target in _HOSTKEY_PROBE_AUTH_NOISE_TARGETS:
        t = target.lower()
        if t.startswith(lower) or lower.startswith(t):
            return True
    # Developing username with no @ yet (chunk may end mid-`user@host`).
    if re.match(r"^[^@\s:]+$", s):
        return True
    if "@" not in s:
        return False
    # Developing `user@host: Permission denied...` (host may contain IPv6
    # colons / brackets). Separator is the final `:\s+` so bare
    # `user@2001:db8::1` (no message yet) stays held.
    m = re.match(r"^[^@\s]*@.+:\s+(.*)$", s, re.DOTALL)
    if not m:
        # Still reading user@host before the message separator.
        return True
    rest = m.group(1)
    if rest == "":
        return True
    rest_l = rest.lower()
    for target in _HOSTKEY_PROBE_AUTH_NOISE_TARGETS:
        t = target.lower()
        if t.startswith(rest_l) or rest_l.startswith(t):
            return True
    return False


def _forward_hostkey_probe_stderr(src, dest) -> None:
    """Tee probe stderr, dropping only auth-none failure noise lines."""
    buf = ""
    while True:
        chunk = src.read(256)
        if not chunk:
            break
        buf += chunk
        while True:
            nl = buf.find("\n")
            if nl < 0:
                break
            line, buf = buf[:nl + 1], buf[nl + 1:]
            if _is_hostkey_probe_auth_noise(line):
                continue
            dest.write(line)
            dest.flush()
        if buf and not _could_be_hostkey_probe_auth_noise_prefix(buf):
            dest.write(buf)
            dest.flush()
            buf = ""
    if buf:
        if _is_hostkey_probe_auth_noise(buf):
            return
        dest.write(buf)
        dest.flush()


def _run_hostkey_probe_ssh(argv: list[str], env: dict) -> int:
    """Run an auth-none host-key probe: inherit stdin (yes/no), filter stderr.

    Only the expected `user@host: Permission denied (...)` auth-none noise is
    dropped. Fingerprints, host-key prompts, warnings, and transport errors
    stay visible.
    """
    try:
        proc = subprocess.Popen(
            argv, env=env,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as e:
        print(f"wtssh: host-key probe failed to start: {e}", file=sys.stderr)
        return 1
    assert proc.stderr is not None
    try:
        _forward_hostkey_probe_stderr(proc.stderr, sys.stderr)
    finally:
        try:
            proc.stderr.close()
        except OSError:
            pass
    return proc.wait()


def _ssh_hostkey_state(host: str, port: str | None) -> str:
    """Last-resort confirmation through a REAL BatchMode connection
    (auth-none): 'verified' means the connection reached the auth stage
    (host key accepted by ssh), 'unverified' means ssh itself rejected the
    key, 'unknown' means transport failed before any of that. Distinguishing
    the three keeps the re-check from both false-dieing on custom
    known_hosts files ssh can see but we cannot enumerate, and from
    false-passing unreachable hosts."""
    ssh_exe = find_bin("ssh")
    if ssh_exe is None:
        return "unknown"
    try:
        r = subprocess.run(
            [ssh_exe, "-o", "BatchMode=yes",
             "-o", "PreferredAuthentications=none",
             "-o", "NumberOfPasswordPrompts=0",
             "-o", "ConnectTimeout=8"]
            + (["-p", str(port)] if port else []) + [host],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if r.returncode == 0:
        # the server accepted auth-none: host key was verified along the way
        return "verified"
    e = r.stderr or ""
    if "Host key verification failed" in e:
        return "unverified"
    if "Permission denied" in e or "Authentications that can continue" in e:
        return "verified"
    return "unknown"


def _probe_env() -> dict:
    """An environment for interactive probes: every askpass carrier is
    stripped, so the ONLY place questions can be answered is the terminal."""
    env = dict(os.environ)
    for k in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "WTSSH_ASKPASS_MAP",
              "WTSSH_PASSPHRASE"):
        env.pop(k, None)
    return env


def probe_chain(config_path: str, blocks: list[dict], map_path: Path) -> None:
    """One DISPATCH-ASSISTED pass through the rendered chain, run after
    unwrap/config/map write, BEFORE the real connection. The probe tree
    runs WITH the dispatcher: INNER tunnels authenticate from the askpass
    map (NO terminal passphrase typing), and a host-key confirmation at
    ANY layer is put to the user as a native Yes/No dialog that shows
    ssh's full fingerprint prompt (WTSSH_ASKPASS_GUI branch of __askpass;
    that string is generated locally by the ssh client, and
    password/kbdint are off in these blocks, so it cannot be
    server-forged). Declines and unconfirmed blocks are caught by the
    offline re-check afterwards, naming the host. The outer probe
    destination is the LAST block: wtssh-target for connects, the last hop
    for the FileZilla tunnel's truncated plan (whose config has no target
    block at all). The caller REWRITES the
    map after this returns: one-shot entries consumed here must be whole
    again for the real connection."""
    env = dict(os.environ)
    env["SSH_ASKPASS"] = str(ensure_askpass_dispatcher())
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["WTSSH_ASKPASS_MAP"] = str(map_path)
    env["WTSSH_ASKPASS_GUI"] = "1"
    env["DISPLAY"] = env.get("DISPLAY", ":0")
    # stderr filtered: auth-none Permission denied noise dropped; host-key
    # GUI prompts go through askpass, transport errors stay visible.
    # no ConnectTimeout on the outer process (its waits include dialog
    # answer time); inner blackholes are bounded by the probe config's
    # per-block ConnectTimeout (F2)
    _run_hostkey_probe_ssh(
        [resolve_bin("ssh"), "-F", config_path,
         "-o", "PreferredAuthentications=none",
         "-o", "NumberOfPasswordPrompts=0", blocks[-1]["block"]],
        env)
    still = [b["entry"] for b in blocks
             if not _host_key_known(b["host"], b["port"])
             and _ssh_hostkey_state(b["host"], b["port"]) != "verified"]
    if still:
        die(f"host key(s) for {', '.join(still)} could not be confirmed -- "
            f"declined at the prompt, or that host is unreachable from "
            f"here; connect manually once to inspect and accept each, then "
            f"retry", 4)


def probe_host_keys(dests: list[tuple[str, str, str | None]],
                    strict: bool = True) -> None:
    """Interactive DIRECT host-key probes (legacy entries, and the
    rendered path's first pass). stderr stays on the terminal; each probed
    destination is re-verified offline afterwards. strict=True (legacy):
    an unconfirmed destination dies here, naming it. strict=False
    (rendered first pass): probing failure falls through to the
    through-tunnel probe -- a block unreachable directly is NOT a refusal
    (the target's port may be open only via the jump)."""
    if os.environ.get("WTSSH_NO_HOSTKEY_PROBE") == "1":
        return
    ssh = resolve_bin("ssh")
    env = _probe_env()
    for label, host, port in dests:
        if not host or _host_key_known(host, port):
            continue
        lookup = f"[{host}]:{port}" if port else host
        base = [ssh, "-o", "PreferredAuthentications=none",
                "-o", "NumberOfPasswordPrompts=0",
                "-o", "ConnectTimeout=8"]
        if port:
            base += ["-p", str(port)]
        print(f"wtssh: host key for {label} ({lookup}) is not known yet; "
              f"confirm it in the terminal (your normal ssh policy)",
              file=sys.stderr)
        # stdin inherited for yes/no; stderr filtered so auth-none
        # `user@host: Permission denied` does not look like a real login miss
        _run_hostkey_probe_ssh(base + [host], env)
        if _host_key_known(host, port):
            continue
        state = _ssh_hostkey_state(host, port)
        # soft (rendered first pass): only an explicit REFUSAL dies here --
        # "unknown" means unreachable directly, exactly what the
        # through-tunnel probe (step 2) exists for; strict
        # (legacy, no tunnel to fall back to): anything unconfirmed dies
        if state == "unverified" or (strict and state != "verified"):
            manual = (f"ssh -p {port} {host}" if port else f"ssh {host}")
            die(f"host key for {label} ({lookup}) could not be confirmed -- "
                f"declined at the prompt, or the host is unreachable from "
                f"here; connect manually once ('{manual}') to inspect and "
                f"accept it, then retry", 4)


def _chain_unlock_keys(plan_keys: list[str], name: str, dest: str,
                       extra_keys: tuple[str, ...] = (),
                       ctx_msgid: str = "pin_chain_batch",
                       ) -> dict[str, tuple[bytes, str]]:
    """Phases 1-3 of the rendered-chain secret materialization:
    (1) load+validate EVERY blob envelope (a corrupt blob dies BEFORE the
    dialog), (2) ONE unwrap-many call -- PCP does not re-prompt within a key
    handle, so the whole batch costs a single PIN gesture -- (3) payload
    checks. `extra_keys` folds additional blobs (the FileZilla tunnel's
    export key) into the SAME gesture, deduplicated by key name. Returns
    {keyname: (keydata, passphrase)}; nothing is written to disk here."""
    keys: list[str] = []
    for k in list(plan_keys) + list(extra_keys):
        if k not in keys:
            keys.append(k)
    pending = []  # (key, raw, obj)
    for key in keys:
        blob = vault_key_path(disk_key_name(key))
        if not blob.exists():
            die(f"vault key '{key}' does not exist ('wtssh key list' "
                f"shows them)", 4)
        raw = blob.read_bytes()
        pending.append((key, raw,
                        vault_load_blob(raw, f"key '{key}'", KEY_AAD)))
    unlocked: dict[str, tuple[bytes, str]] = {}
    if not pending:
        return unlocked
    batch_ctx = pin_text(ctx_msgid, name=name, dest=dest,
                         keys=", ".join(k for k, _, _ in pending))
    deks = vault_unwrap_many(
        [base64.b64decode(obj["wdek"]) for _, _, obj in pending],
        batch_ctx)
    if len(deks) != len(pending):  # unreachable: vault_unwrap_many guards
        die("internal error: batch unwrap count mismatch", 2)
    for (key, raw, obj), dek in zip(pending, deks):
        payload = vault_open_payload(KEY_AAD, disk_key_name(key),
                                     raw, f"key '{key}'", batch_ctx,
                                     dek=dek)
        container = payload.get("key")
        pw = payload.get("passphrase")
        if not isinstance(container, str) or not isinstance(pw, str):
            die(f"key '{key}' payload is missing its key material; "
                f"re-import it ('wtssh key remove {key}' + "
                f"'wtssh key import {key} <file>')", 4)
        unlocked[key] = (base64.b64decode(container), pw)
        audit_log("verbose", f"unwrapped key '{key}' for {name!r}")
    return unlocked


def _chain_materialize_run(plan: dict, argv: list[str], rundir: Path,
                           unlocked: dict[str, tuple[bytes, str]],
                           no_askpass: bool) -> dict:
    """Containers, the -F config and the askpass map from unlocked payloads
    -- all inside the caller-owned `rundir` plus %TEMP% keydirs -- then the
    two-layer host-key precheck (direct probes first, dispatch-assisted
    through-tunnel probes for what stayed unknown). Returns the run dict:
    containers/keydirs/map_path/cfg_path/dispatch/ssh_exe."""
    containers: dict[str, str] = {}   # keyname -> container path
    keydirs: list[Path] = []
    map_entries: dict[str, dict] = {}  # truncated container path -> entry
    try:
        for key in plan["keys"]:
            keydata, pw = unlocked[key]
            tmpdir, keyfile = secure_mkkey(keydata)
            keydirs.append(tmpdir)
            containers[key] = str(keyfile)
            if pw:
                # one-shot PER USE: count every block referencing this key
                # (one key authorized as both a hop's and the target's
                # identity is a legitimate topology -- each of those
                # prompts must be served exactly once)
                uses = sum(1 for b in plan["blocks"]
                           for i in b["identities"] if i.get("key") == key)
                map_entries[str(keyfile)[:ASKPASS_PROMPT_MAX]] = {
                    "pw": pw, "uses": max(uses, 1)}
        ssh_exe = resolve_bin(argv[0])
        cfg_path = rundir / "config"
        dispatch = bool(plan["keys"]) and not no_askpass
        atomic_write(cfg_path, render_config(plan["blocks"], containers,
                                             str(cfg_path), ssh_exe,
                                             dispatch=dispatch)
                     .encode("utf-8"))
        apply_owner_only_dacl(cfg_path)
        map_path = rundir / "askpass-map.json"
        if dispatch:
            write_askpass_map(map_path, map_entries, None)
        if dispatch and os.environ.get("WTSSH_NO_HOSTKEY_PROBE") != "1":
            unknown = [b for b in plan["blocks"]
                       if not _host_key_known(b["host"], b["port"])]
            if unknown:
                # 跳板链拓扑：只有首块由本机直拨，其余块由上一跳拨号
                # （ProxyCommand），本机直连探测注定超时（每块最多 2x8s：
                # probe + BatchMode 复验）。首块仍走终端明示确认，
                # 下游块直落隧道对话框。
                if len(plan["blocks"]) > 1:
                    first_block = plan["blocks"][0]["block"]
                    direct = [b for b in unknown
                              if b["block"] == first_block]
                    skipped = [b for b in unknown
                               if b["block"] != first_block]
                else:
                    direct = unknown
                    skipped = []
                if direct:
                    names = ", ".join(b["entry"] for b in direct)
                    # 1) DIRECT interactive probes first: a publicly reachable
                    #    block confirms with NO tunnel and therefore NO key
                    #    passphrase typed (PA=none offers no credential)
                    print(f"wtssh: confirming unknown host key(s) for {names} "
                          f"in the terminal before dispatch", file=sys.stderr)
                    probe_host_keys([(b["entry"], b["host"], b["port"])
                                     for b in direct], strict=False)
                if skipped:
                    names0 = ", ".join(b["entry"] for b in skipped)
                    print(f"wtssh: {names0} sit(s) behind jump host(s); "
                          f"skipping direct probe",
                          file=sys.stderr)
                # 2) a block that stayed unknown (direct-probed but unconfirmed,
                #    or skipped as jump-only) -- confirm it THROUGH the tunnel, dispatch-assisted:
                #    tunnels authenticate from the askpass map (no
                #    passphrase typing) and each unknown host key is put
                #    to a native Yes/No dialog with its full fingerprint
                still = [b for b in unknown
                         if not _host_key_known(b["host"], b["port"])]
                if still:
                    names2 = ", ".join(b["entry"] for b in still)
                    skipped_blocks = {b["block"] for b in skipped}
                    if any(b["block"] in skipped_blocks for b in still):
                        print(f"wtssh: {names2} sit(s) behind jump host(s); "
                              f"confirming through the tunnel (a dialog will ask "
                              f"for each unknown host key)", file=sys.stderr)
                    else:
                        print(f"wtssh: {names2} is not directly reachable; "
                              f"confirming through the tunnel (a dialog will ask "
                              f"for each unknown host key)", file=sys.stderr)
                    # probe-variant config: ConnectTimeout lives in the
                    # BLOCKS (the only place inner tunnel sshs read it)
                    probe_cfg = rundir / "config.probe"
                    atomic_write(probe_cfg, render_config(
                        plan["blocks"], containers, str(probe_cfg), ssh_exe,
                        dispatch=dispatch, probe=True).encode("utf-8"))
                    apply_owner_only_dacl(probe_cfg)
                    probe_chain(str(probe_cfg), plan["blocks"], map_path)
                    # the probe consumed one-shot map entries -- restore
                    # the full map for the real connection
                    write_askpass_map(map_path, map_entries, None)
        if dispatch:
            # a passphrase-protected PLAIN key file on any block cannot be
            # served by the dispatcher -- say so before ssh fails on it
            for b in plan["blocks"]:
                for ident in b["identities"]:
                    if ident["kind"] != "file":
                        continue
                    enc = key_encrypted(Path(ident["path"]))
                    if enc:
                        print(f"wtssh: warning: key file {ident['path']} "
                              f"(entry {b['entry']}) is passphrase-protected; "
                              f"the dispatcher cannot answer it -- import it "
                              f"into the vault ('wtssh key import') or use "
                              f"--no-askpass", file=sys.stderr)
    except BaseException:
        # a mid-materialize die (host-key probe refusal, a failed write,
        # ...) must not strand the already-decrypted containers: the
        # caller only learns the keydir paths on a SUCCESSFUL return
        wipe_session_dirs(keydirs)
        raise
    return {"containers": containers, "keydirs": keydirs,
            "map_path": map_path if dispatch else None,
            "cfg_path": cfg_path, "dispatch": dispatch, "ssh_exe": ssh_exe}


def _chain_launch_argv(plan: dict, argv: list[str], run: dict,
                       dest_block: str = BLOCK_TARGET) -> list[str]:
    """The rendered run's ssh argv: -F the session config; -i/-J pairs are
    gone (identities and the chain live in the config); the destination is
    the opaque block name (BLOCK_TARGET for connects, the last hop for the
    FileZilla SOCKS tunnel). First-position PA=no hardening whenever any
    block authenticates by vault key (first-obtained-wins in argv: the
    session passphrase must never be feedable to a login prompt)."""
    new_argv = rebuild_target_argv(argv, str(run["cfg_path"]), dest_block)
    assert new_argv is not None  # build_render_plan already vetted it
    if any(i["kind"] == "keyref" for b in plan["blocks"]
           for i in b["identities"]):
        s = 1  # right after the program token, before -F
        new_argv = (new_argv[:s]
                    + ["-o", "PasswordAuthentication=no",
                       "-o", "ChallengeResponseAuthentication=no"]
                    + new_argv[s:])
    return new_argv


def connect_rendered(args, p: dict, argv: list[str], plan: dict) -> None:
    """The rendered/dispatch connect path. Unwraps one container per
    distinct vault key with a SINGLE CNG PIN (batch unwrap), renders the -F
    config and the askpass map into an owner-only run dir, runs ssh, then
    wipes everything -- cleanup failures are COLLECTED so ssh's exit code
    always wins. WTSSH_RENDER_DRY=1 materializes nothing and
    prints the plan as JSON instead (offline inspection / golden tests)."""
    name = p["name"][len(PREFIX):]
    dest = entry_dest_label(p)
    dry = os.environ.get("WTSSH_RENDER_DRY") == "1"
    no_askpass = getattr(args, "no_askpass", False)

    if not dry:
        sweep_orphan_keydirs()
        sweep_orphan_rundirs()

    rundir: Path | None = None
    keydirs: list[Path] = []
    rc: int | None = None
    try:
        if dry:
            ssh_exe = resolve_bin(argv[0])
            containers = {key: str(Path(tempfile.gettempdir())
                                   / "wtssh-key-dryrun" / "key")
                          for key in plan["keys"]}
            # `run` owns stdout for the remote output (purity contract),
            # so its dry-run report goes to stderr instead
            out = sys.stderr if getattr(args, "cmd", None) == "run" \
                else sys.stdout
            print(json.dumps({
                "dryRun": True,
                "name": name,
                "sshExe": ssh_exe,
                "argv": rebuild_target_argv(argv, "<config>"),
                "mapEntries": 0,
                "blocks": plan["blocks"],
                "config": render_config(plan["blocks"], containers,
                                        "<config>", ssh_exe,
                                        dispatch=bool(plan["keys"])),
            }, ensure_ascii=False, indent=2), file=out)
            return
        if plan["keys"] and agent_wanted(args):
            # PIN-free fast path: every key verified live in ssh-agent by
            # fingerprint just now. Dry runs never reach here (offline).
            pubs = agent_coverage(plan["keys"])
            if pubs is not None:
                connect_agent_rendered(args, p, argv, plan, pubs)
                return  # exits by itself; kept for readability
        unlocked = _chain_unlock_keys(plan["keys"], name, dest)
        if agent_wanted(args):
            # Unwrap-triggered auto-stage: this PIN also refreshes the 1h
            # agent cache so the NEXT connect skips the PIN. Best-effort --
            # failures only warn; this session continues with containers.
            agent_stage_unlocked(unlocked, source=f"connect {name}")
        rundir = make_run_dir()
        run = _chain_materialize_run(plan, argv, rundir, unlocked, no_askpass)
        keydirs = run["keydirs"]
        new_argv = _chain_launch_argv(plan, argv, run)
        if run["dispatch"]:
            # the map and the encrypted-file warning were handled inside
            # _chain_materialize_run; here only the env wiring
            env = dispatch_env(run["map_path"])
        else:
            env = dict(os.environ)
        audit_log("verbose", f"rendered chain for {name!r}: "
                   f"{len(plan['blocks']) - 1} hop(s), "
                   f"{len(plan['keys'])} vault key(s)")
        rc = subprocess.run(new_argv, env=env).returncode
    finally:
        wipe_session_dirs(keydirs + [rundir])
    sys.exit(rc if rc is not None else 1)


def _agent_ssh_env() -> dict:
    """Child env for the agent branch: inherit, minus every askpass
    carrier. A stale WTSSH_ASKPASS_MAP (e.g. exported by a sibling
    session) must never ride an agent ssh -- its map could answer prompts
    this session never registered. SSH_ASKPASS_REQUIRE=force without
    SSH_ASKPASS is harmless but pointless -- drop it too, and the retired
    WTSSH_PASSPHRASE defensively (mirrors dispatch_env). Side effect,
    accepted: a user-exported SSH_ASKPASS of their own is also dropped --
    the branch claims "no dispatcher", and a terminal prompt (instead of
    their askpass) is the consistent direction for mixed
    plaintext-encrypted entries."""
    env = dict(os.environ)
    for var in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "WTSSH_ASKPASS_MAP",
                "WTSSH_PASSPHRASE"):
        env.pop(var, None)
    return env


def connect_agent_rendered(args, p: dict, argv: list[str], plan: dict,
                           pubs: dict[str, str]) -> None:
    """The agent branch of the rendered path: every vault key is live in
    ssh-agent (fingerprint-verified by the caller), so no PIN, no
    containers, no dispatcher. Blocks keep their shape; keyref identities
    become pub-file selectors (`IdentityFile <pub>` + `IdentitiesOnly yes`
    points ssh at exactly that agent identity -- the standard pub-naming
    trick). Deliberately WITHOUT the PA-no hardening: there is no session
    passphrase to protect, and the terminal password fallback stays
    available. Host-key confirmation stays fully interactive (no forced
    askpass, hence no pre-probes). Exits by itself."""
    name = p["name"][len(PREFIX):]
    rundir = make_run_dir()
    try:
        blocks = []
        for b in plan["blocks"]:
            idents = [{"kind": "file", "path": pubs[i["key"]]}
                      if i["kind"] == "keyref" else i
                      for i in b["identities"]]
            blocks.append({**b, "identities": idents})
        ssh_exe = resolve_bin(argv[0])
        cfg_path = rundir / "config"
        atomic_write(cfg_path, render_config(blocks, {}, str(cfg_path),
                                             ssh_exe, dispatch=False)
                     .encode("utf-8"))
        apply_owner_only_dacl(cfg_path)
        new_argv = rebuild_target_argv(argv, str(cfg_path))
        assert new_argv is not None  # build_render_plan already vetted it
        print(f"wtssh: note: keys {', '.join(plan['keys'])} are cached in "
              f"ssh-agent -- connecting without a TPM PIN", file=sys.stderr)
        audit_log("verbose", f"agent branch for {name!r}: "
                  f"{len(plan['keys'])} cached key(s)")
        rc = subprocess.run(new_argv, env=_agent_ssh_env()).returncode
    finally:
        wipe_session_dirs([rundir])
    sys.exit(rc if rc is not None else 1)


def connect_agent_legacy(args, argv: list[str],
                         refs: list[tuple[Path, str]],
                         pubs: dict[str, str]) -> None:
    """The agent branch of the legacy (unrenderable-chain) path: only
    reachable with exactly one vault ref (multi-ref legacy dies earlier).
    Swap `-i wtv:KEY` for the pub selector, pin IdentitiesOnly so ssh
    offers exactly that agent identity, run with no PIN, no container, no
    dispatcher. Only the OPTION region is rewritten, so a remote command's
    own `-i` is left alone (same boundary as argv_key_refs). Exits."""
    _blob, keyname = refs[0]
    pub = pubs[keyname]
    # Rewrite the OPTION region only: stop at the destination (the first
    # bare token), so a remote command keeps its own `-i` -- the same
    # boundary argv_key_refs / rebuild_target_argv / key remove honor
    # (rewrite_key_arg, the PIN path's rewriter, has no such stop; the
    # agent branch is deliberately stricter here). The swap test mirrors
    # the PIN path exactly (resolve_key_ref: valid spelling required), so
    # a hand-mangled `-i wtv:` rides verbatim on BOTH paths (F5).
    # Plain (non-vault) -i identities ride along untouched.
    new_argv: list[str] = []
    dest_seen = False
    i = 1
    new_argv.append(argv[0])  # the program token is never an identity
    while i < len(argv):
        t = argv[i]
        if dest_seen:
            new_argv.append(t)
            i += 1
            continue
        if t == "-i" and i + 1 < len(argv):
            ref = resolve_key_ref(shunquote(argv[i + 1]))
            if ref is not None and ref[1] == keyname:
                new_argv += ["-i", pub]
            else:
                new_argv += [t, argv[i + 1]]
            i += 2
            continue
        if t in VALUE_OPTS and i + 1 < len(argv):
            new_argv += [t, argv[i + 1]]
            i += 2
            continue
        if t.startswith("-") and len(t) > 1:
            new_argv.append(t)
            i += 1
            continue
        dest_seen = True
        new_argv.append(t)
        i += 1
    s = option_region_start(new_argv)
    new_argv = new_argv[:s] + ["-o", "IdentitiesOnly=yes"] + new_argv[s:]
    print(f"wtssh: note: key '{keyname}' is cached in ssh-agent -- "
          f"connecting without a TPM PIN", file=sys.stderr)
    audit_log("verbose", f"agent legacy branch for key '{keyname}'")
    sys.exit(subprocess.run(new_argv, env=_agent_ssh_env()).returncode)


def _gui_yesno(text: str, title: str) -> bool:
    """Native Yes/No dialog (host-key confirmation and the --to-clipboard
    secondary confirmation). Both text and title travel base64-encoded to
    dodge every quoting pitfall; powershell's exit code is the answer. Any
    dialog failure is fail-closed (returns False)."""
    import base64 as _b64
    b64 = _b64.b64encode(text.encode("utf-8")).decode("ascii")
    t64 = _b64.b64encode((title or "wtssh").encode("utf-8")).decode("ascii")
    ps = ("Add-Type -AssemblyName System.Windows.Forms; "
          f"$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
          f"'{b64}')); "
          f"$ttl=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
          f"'{t64}')); "
          "$r=[System.Windows.Forms.MessageBox]::Show($t, $ttl, "
          "'YesNo', 'Warning'); if ($r -eq [System.Windows.Forms.DialogResult]::Yes) "
          "{ exit 0 } else { exit 1 }")
    ps_exe = find_bin("powershell")
    if ps_exe is None:
        return False
    try:
        r = subprocess.run([ps_exe, "-NoProfile", "-Command", ps],
                           timeout=120)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def confirm_password_to_clipboard(name: str, dest: str) -> bool:
    """Explicit secondary confirmation for --to-clipboard (displayed, not
    silent): a native Yes/No dialog naming the entry identity plus the
    clipboard risks. Fail-closed -- any dialog failure reads as declined."""
    t = ui_texts()
    body = t["clip_confirm_body"].format(name=name, dest=dest)
    return _gui_yesno(body, t["clip_confirm_title"])


def _askpass_map_path() -> Path | None:
    map_file = os.environ.get("WTSSH_ASKPASS_MAP")
    return Path(map_file) if map_file else None


def _load_askpass_map() -> dict:
    """Strict schema v2 (MAP_SCHEMA_VERSION). The map is written and
    consumed within a single connect, so there is no legacy shape and
    nothing to tolerate: any other structure is a fail-closed miss with a
    reason."""
    map_file = _askpass_map_path()
    if map_file is None:
        raise _AskMiss("no askpass map is registered")
    try:
        entries = json.loads(map_file.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise _AskMiss(f"askpass map unreadable: {e}")
    if not isinstance(entries, dict) or entries.get("v") != MAP_SCHEMA_VERSION:
        raise _AskMiss(f"askpass map is not schema {MAP_SCHEMA_VERSION}")
    if not isinstance(entries.get("keys", {}), dict):
        raise _AskMiss("askpass map keys slot is malformed")
    return entries


def _save_askpass_map(entries: dict) -> None:
    """Persist the consumed/decremented map: atomic AND owner-only -- a
    plain atomic_write would land the replaced file under the token default
    ACL, silently widening the remaining passphrases' readability. A failed
    save (OSError or a DACL error) is a warning, not a crash: the prompt is
    answered anyway and only the decremented count/tombstone is lost, so
    the same passphrase may be served once more within this session's
    remaining uses."""
    map_file = _askpass_map_path()
    if map_file is None:
        return
    try:
        atomic_write_owner_only(
            map_file,
            json.dumps(entries, ensure_ascii=False).encode("utf-8"))
    except OSError as e:
        print(f"wtssh: warning: could not update askpass map: {e}",
              file=sys.stderr)


def _entry_uses(entry: dict) -> int:
    try:
        return int(entry.get("uses", 1))
    except (TypeError, ValueError):
        return 1


def _askpass_key_pw(entries: dict, prompt: str) -> str:
    """The keys slot: answer ONLY prompts shaped
    `passphrase for key '<path>'` whose path is registered (full, %.100s
    truncated, or case-folded). One-shot PER USE; a consumed entry leaves a
    tombstone so a retry reads as 'already handed out', not 'never
    registered' (it is the only clue a user gets when a key cannot be
    answered)."""
    keys = entries.get("keys") or {}
    m = re.search(r"passphrase for key '([^']*)'", prompt)
    if not m:
        raise _AskMiss("prompt carries no quoted key path")
    path = m.group(1)
    hit = None
    for cand in (path, path[:ASKPASS_PROMPT_MAX]):
        if cand in keys:
            hit = cand
            break
    if hit is None:
        fold = {k.casefold(): k for k in keys}
        hit = fold.get(path[:ASKPASS_PROMPT_MAX].casefold())
    if hit is None:
        raise _AskMiss(f"key path is not registered: "
                       f"{path[:ASKPASS_PROMPT_MAX]!r}")
    entry = keys[hit]
    if entry is None:
        raise _AskMiss("this key's passphrase was already handed out "
                       "(one-shot dispatch per use)")
    if not isinstance(entry, dict) or not isinstance(entry.get("pw"), str):
        raise _AskMiss("askpass map entry is malformed")
    # The same vault key legitimately appears on more than one block of a
    # chain (one key authorized as both the jump's and the target's
    # identity): each of those prompts is served exactly once, bounded by
    # the number of blocks sharing the container.
    uses = _entry_uses(entry)
    keys[hit] = None if uses <= 1 else {"pw": entry["pw"], "uses": uses - 1}
    _save_askpass_map(entries)
    audit_log("verbose",
              f"askpass dispatched a key passphrase "
              f"({len(keys)} registered)")
    return entry["pw"]


# OpenSSH's client-generated password prompt (`<user>@<host>'s password: `).
# Group 1 is greedy, so the split lands on the LAST '@' -- the same
# rsplit('@', 1) semantics cmd_fields uses for destinations.
_PASSWORD_PROMPT_RE = re.compile(r"^(.+)@(.+)'s password:\s*$")


def _askpass_login_pw(entries: dict, prompt: str) -> str:
    """The login slot (stored secret): answer ONLY the client-generated
    `<user>@<host>'s password:` prompt for an identity registered at
    connect time (the target's own login identity). Keyboard-interactive
    text is server-controlled and never matches (and its channel is shut
    off by the connect's own -o); jump identities are deliberately NOT
    registered -- a hop asking for a password gets an empty answer and
    fails fast instead of collecting the target's login password."""
    login = entries.get("login")
    if not login:
        raise _AskMiss("no login credential is registered for this session")
    if not isinstance(login, dict) or not isinstance(login.get("pw"), str):
        raise _AskMiss("askpass map login slot is malformed")
    m = _PASSWORD_PROMPT_RE.match(prompt)
    if not m:
        raise _AskMiss("prompt is not a password-shaped prompt")
    identity = f"{m.group(1)}@{m.group(2)}"
    ids = login.get("identities")
    if not isinstance(ids, list) or identity not in ids:
        raise _AskMiss(f"identity is not registered for login dispatch: "
                       f"{identity!r}")
    uses = _entry_uses(login)
    if uses <= 0:
        raise _AskMiss("the login credential's uses are exhausted")
    login["uses"] = uses - 1
    _save_askpass_map(entries)
    audit_log("verbose",
              f"askpass dispatched the login password "
              f"({uses - 1} use(s) left)")
    return login["pw"]


def action_askpass(args):
    """SSH_ASKPASS dispatcher. Strict map schema v2 with two
    typed slots: `keys` answers key-passphrase prompts (one-shot per use,
    consumed -> tombstone), `login` answers the target's standard password
    prompt for registered identities only. Everything else is refused with
    an empty line -- ssh then skips the key / the auth fails -- plus one
    stderr reason line and an audit entry, which is the diagnosis ssh
    itself will not give."""
    prompt = " ".join(args.prompt or [])
    try:
        entries = _load_askpass_map()
        if "passphrase for key" in prompt:
            pw = _askpass_key_pw(entries, prompt)
        else:
            pw = _askpass_login_pw(entries, prompt)
        sys.stdout.write(pw + "\n")
        return
    except _AskMiss as e:
        # probe-mode only: ANY non-key prompt that reaches askpass here is
        # a LOCALLY-generated question -- in the probe configs password and
        # keyboard-interactive are off and the outer runs PA=none, so a
        # server has no channel to inject text into askpass. The classic
        # shape is the host-key confirmation (its text carries the full
        # fingerprint), but the exact phrasing is build-dependent (it may
        # not match the classic shape on a given ssh build), so the gate is
        # deliberately shape-agnostic: show the
        # user whatever ssh asked, in a native Yes/No dialog. The tool only
        # asks -- it never auto-accepts; No/cancel/dialog
        # failure answers "no" and ssh fails closed.
        if os.environ.get("WTSSH_ASKPASS_GUI") == "1" \
                and "passphrase for key" not in prompt:
            # carve-out: a KEY-shaped miss carries the
            # dispatcher's one-shot diagnostic trail (not-registered /
            # already-handed-out); dialoging it would mask that line and
            # feed "yes" to ssh as a passphrase guess. Anything else here is
            # a locally-built question -> dialog.
            audit_log("verbose",
                      f"askpass probe dialog for prompt: {prompt!r}")
            body = f"{ui_texts()['hostkey_dialog']}\n\n{prompt}"
            sys.stdout.write("yes\n" if _gui_yesno(body, "wtssh") else "no\n")
            return
        audit_log("warn", f"askpass miss: {e}")
        print(f"wtssh: askpass: {e}", file=sys.stderr)
        sys.stdout.write("\n")


def checked_forward_spec(spec: str) -> str:
    """--tunnel-forward LOCAL_PORT:REMOTE_HOST:REMOTE_PORT guard: numeric
    ports in range, a conservative remote-host charset (alnum .-_ covers
    names and IPv4; IPv6 would break the 3-way split and is not accepted),
    so nothing surprising can ride into the ssh argv."""
    parts = spec.split(":")
    if len(parts) != 3 or not all(parts):
        die("--tunnel-forward expects LOCAL_PORT:REMOTE_HOST:REMOTE_PORT "
            "(e.g. 2222:127.0.0.1:22)")
    lp, rh, rp = parts
    if not (lp.isdigit() and rp.isdigit()
            and 0 < int(lp) <= 65535 and 0 < int(rp) <= 65535):
        die("--tunnel-forward ports must be numeric and within 1-65535")
    bad = sorted({c for c in rh if not (c.isalnum() or c in ".-_")})
    if bad:
        die(f"--tunnel-forward remote host contains unsupported "
            f"characters: {' '.join(repr(c) for c in bad)}")
    return spec


def action_connect(args):
    extra = getattr(args, "extra", None) or []
    if extra and extra[0] != "ssh":
        # extra exists for WT-routed commandlines ("... connect NAME -- ssh ...");
        # a bare typo after NAME must not be silently swallowed.
        die(f"unexpected argument(s) after name: {' '.join(extra)!r} "
            f"(expected 'ssh ...' from a routed commandline)")

    data = load()
    p = require_profile(data, args.name)
    argv = ssh_argv(p)
    remote = list(getattr(args, "command", None) or [])
    if remote and remote[0] == "--":
        # `run NAME -- cmd...`: argparse REMAINDER already eats the
        # separator on the parser path, so this only fires for direct
        # action_connect callers -- keep it as a defensive no-op
        remote = remote[1:]
    if remote:
        if getattr(args, "tunnel_forward", None):
            # -N means "no remote shell": ssh would silently drop the command
            die("cannot combine --tunnel-forward with a remote command "
                "(pure-forward mode runs no remote shell)")
        tail = cmd_fields(p)["tail"]
        if tail:
            # the entry already ends in a remote command; appending another
            # would concatenate two commands into one ssh invocation --
            # refuse loudly instead of guessing the join
            die(f"entry '{args.name}' already carries a remote command "
                f"({' '.join(tail)}); 'run' cannot append "
                f"another one -- run it bare, or rewrite the options "
                f"('wtssh edit {args.name} --extra \"...\"' replaces the "
                f"option region and drops the tail)")
        argv = argv + remote
    fwd = getattr(args, "tunnel_forward", None)
    if fwd:
        checked_forward_spec(fwd)
        # Pure-forward mode: no remote shell. Inserted at the option region
        # so BOTH paths carry it (the rendered path keeps non -i/-J options
        # verbatim; the legacy path runs this argv as-is).
        at = option_region_start(argv)
        argv[at:at] = ["-N", "-L", fwd]
    refs = argv_key_refs(argv)
    # Rendered jump chain when every link is a book entry we hold
    # identities for; everything else -- including plain direct entries and
    # stored-passphrase targets -- keeps the legacy path below verbatim.
    dry = os.environ.get("WTSSH_RENDER_DRY") == "1"
    try:
        plan, reason = build_render_plan(
            data, p, cmd_fields(p), argv,
            dispatch_active=not getattr(args, "no_askpass", False))
    except SystemExit:
        # the one deliberate die in build_render_plan (a password-auth hop
        # under active dispatch). The refusal must stand for a real connect,
        # but dry runs report it as JSON instead of dying -- the dry
        # contract is "explain, never connect"
        if not dry:
            raise
        plan, reason = None, _LAST_DIE
    if plan is not None:
        connect_rendered(args, p, argv, plan)
        return  # rendered path exits by itself -- except dry runs, which
        # must NOT fall through into the legacy ssh below
    if dry:
        # the documented dry-run promise is "no ssh is started, no vault is
        # touched" -- honor it on the legacy path too: report WHY this entry
        # keeps the -J/direct path instead of silently connecting.
        # (`run` reroutes to stderr: stdout belongs to the remote output.)
        out = sys.stderr if getattr(args, "cmd", None) == "run" \
            else sys.stdout
        print(json.dumps({"dryRun": True, "name": args.name,
                          "rendered": False, "reason": reason, "argv": argv},
                         ensure_ascii=False, indent=2), file=out)
        return
    if reason:
        print(f"wtssh: note: chain keeps the -J path: {reason}",
              file=sys.stderr)
    if not refs and not secret_path(args.name).exists():
        # no vault key, no passphrase: plain connect, zero friction (normal
        # ssh host-key prompting applies; no forced askpass to fight it)
        sys.exit(subprocess.run(argv).returncode)

    # The CNG PIN dialog IS the consent: a tab costs exactly one gesture
    # (cng-vault.ps1 caches the consent at handle level for 1 dialog per
    # process, but WT spawns a process per tab, so that cache never helps
    # across tabs).
    if len(refs) > 1:
        # Rare by design: multi-key entries normally render through the
        # rendered path above. This only fires when the chain ALSO failed to
        # render (the note above printed the reason) -- one session passphrase
        # cannot serve two keys on a legacy -J line.
        die(f"entry '{args.name}' references {len(refs)} vault keys "
            f"({', '.join(name for _path, name in refs)}) and its chain "
            f"cannot render (see the note above or 'wtssh print {args.name}'); "
            f"fix the chain reason or reduce the entry to one vault key", 4)
    if not getattr(args, "no_askpass", False):
        # the same forced-askpass host-key trap as the rendered path: an
        # unknown host key is unanswerable once dispatch is active. Cover
        # the -J hops too -- their confirmations would be
        # swallowed exactly like the target's. Runs only when at least one
        # key is unknown (known_hosts pre-check inside).
        f0 = cmd_fields(p)
        dests = []
        for spec in [s.strip() for s in (f0["jump"] or "").split(",")
                     if s.strip()]:
            _u, h, pt = _parse_hopspec(spec)
            dests.append((spec, h, pt))
        dests.append((args.name, f0["host"], f0["port"]))
        probe_host_keys(dests)
    if refs and agent_wanted(args):
        # PIN-free fast path for the single-key legacy entry (multi-ref
        # legacy died above). Host keys were already confirmed above, and
        # the branch below would cost a CNG PIN -- skip it when the agent
        # already holds the key (fingerprint-verified just now).
        pubs = agent_coverage([name for _path, name in refs])
        if pubs is not None:
            connect_agent_legacy(args, argv, refs, pubs)
    no_askpass = getattr(args, "no_askpass", False)
    if refs:
        # The dispatched passphrase is the KEY's session passphrase. A
        # vault-key entry authenticates by pubkey, so both password prompt
        # channels are shut off at the START of the option region
        # (first-obtained-wins), so no user -o can reinstate them -- and the
        # dispatcher only ever answers key-passphrase prompts anyway. They
        # do NOT propagate into -J hops (a parent's -o does not reach the
        # ProxyCommand subprocess); a password-auth hop under active key
        # dispatch is refused above (exit 4), so nothing on this path can
        # collect the key passphrase.
        s = option_region_start(argv)
        argv = (argv[:s]
                + ["-o", "PasswordAuthentication=no",
                   "-o", "ChallengeResponseAuthentication=no"]
                + argv[s:])
    dest = entry_dest_label(p)
    pw = None
    keydata = None
    keyfile = None
    tmpdir = None
    login: dict | None = None   # stored-secret slot: pw + registered identity
    if refs:
        blob, keyname = refs[0]
        if not blob.exists():
            die(f"entry '{args.name}' references vault key '{keyname}', which "
                f"does not exist ('wtssh key list' shows them)", 4)
        ctx = pin_text("pin_connect_key", name=args.name, dest=dest,
                       key=keyname)
        payload = vault_open_payload(KEY_AAD, keyname, blob.read_bytes(),
                                     f"key '{keyname}'", ctx)
        container = payload.get("key")
        pw = payload.get("passphrase")
        if not isinstance(container, str) or not isinstance(pw, str):
            die(f"key '{keyname}' payload is missing its key material; "
                f"re-import it ('wtssh key remove {keyname}' + "
                f"'wtssh key import {keyname} <file>')", 4)
        keydata = base64.b64decode(container)
        if agent_wanted(args):
            # Same unwrap-triggered auto-stage as the rendered path: this
            # PIN refreshes the 1h agent cache for the next connect.
            agent_stage_unlocked({keyname: (keydata, pw)},
                                 source=f"connect {args.name}")
    elif secret_path(args.name).exists():
        if no_askpass:
            # explicit opt-out, honored exactly like the rendered path:
            # no PIN, no dispatch -- ssh asks on the terminal
            print(f"wtssh: note: --no-askpass: the stored passphrase for "
                  f"'{args.name}' will be asked on the terminal",
                  file=sys.stderr)
        else:
            pw = secret_load(args.name,
                             pin_text("pin_connect", name=args.name,
                                      dest=dest))
            # Option A gate: the dispatcher answers ONLY the standard
            # `<user>@<host>'s password:` prompt, and only for the identity
            # this commandline logs in with. Jump identities are
            # deliberately NOT registered: an alias hop's resolved name is
            # unknowable offline, and a hop's password prompt must not
            # collect the target's login password (it gets an empty answer
            # and fails fast instead).
            f0 = cmd_fields(p)
            if not f0["host"]:
                die(f"entry '{args.name}' has no parsable host", 4)
            login_user = f0["user"] or os.environ.get("USERNAME") or ""
            login = {"pw": pw, "uses": 3,
                     "identities": [f"{login_user}@{f0['host']}"]}

    # Reclaim stale key dirs and run dirs from killed sessions before making
    # our own (safe against live sessions in other tabs: owner.pid liveness
    # check). The legacy path now creates a run dir too (the askpass map is
    # a secret carrier), so both sweepers run here exactly like the rendered
    # path -- a hard-killed legacy session must not strand its map until
    # some future rendered connect happens to sweep it.
    sweep_orphan_keydirs()
    sweep_orphan_rundirs()
    rundir: Path | None = None
    rc: int | None = None
    try:
        if keydata is not None:
            tmpdir, keyfile = secure_mkkey(keydata)
        if keyfile is not None:
            argv = rewrite_key_arg(argv, str(keyfile))
        if pw is not None and not no_askpass:
            ok, ver = ssh_askpass_support()
            if not ok:
                print(f"wtssh: warning: {ver} predates SSH_ASKPASS_REQUIRE "
                      f"(OpenSSH 8.4); the passphrase prompt will appear on "
                      f"the terminal instead of the hidden askpass flow",
                      file=sys.stderr)
            rundir = make_run_dir()
            map_path = rundir / "askpass-map.json"
            if login is not None:
                # password auth served from the login slot: shut the
                # keyboard-interactive channel (server-controlled prompt
                # text) off entirely, the same channel hardening the
                # rendered path applies to key entries -- the server can
                # then only ask via the one prompt shape the dispatcher
                # serves. NumberOfPasswordPrompts is pinned to the login
                # slot's uses=3 so the dispatch contract holds no matter
                # what the user's config sets (kbdint-only servers fail
                # fast, by decision)
                s = option_region_start(argv)
                argv = (argv[:s]
                        + ["-o", "ChallengeResponseAuthentication=no",
                           "-o", "NumberOfPasswordPrompts=3"]
                        + argv[s:])
                write_askpass_map(map_path, {}, login)
            else:
                write_askpass_map(map_path, {
                    str(keyfile)[:ASKPASS_PROMPT_MAX]: {"pw": pw, "uses": 1}
                }, None)
            env = dispatch_env(map_path)
        else:
            # no dispatch (--no-askpass honored, or nothing to dispatch):
            # never leave a stale passphrase carrier in the child env
            env = dict(os.environ)
            env.pop("WTSSH_PASSPHRASE", None)
        rc = subprocess.run(argv, env=env).returncode
    finally:
        # the askpass map is a secret carrier: wiped with the same priority
        # as the decrypted containers; ssh's exit code wins over cleanup
        # failures (R6)
        wipe_session_dirs([tmpdir, rundir])
    sys.exit(rc)


def rewrite_key_arg(argv: list[str], new_key: str) -> list[str]:
    """Point every -i that names a vault key (`-i wtv:<name>`) at the decrypted
    copy. Jump-host entries (-J) keep their own -J tokens verbatim."""
    out = list(argv)
    i = 0
    while i < len(out):
        if out[i] == "-i" and i + 1 < len(out) \
                and resolve_key_ref(out[i + 1]) is not None:
            out[i + 1] = new_key
            i += 2
            continue
        i += 1
    return out


_TOKEN_USER_SID: str | None = None


def _token_user_sid_string() -> str:
    """The process token's user SID as an SDDL-ready string (cached -- the
    token cannot change within one run). ctypes/advapi32 only: no pywin32.
    Raises DaclError on any failure: without a trustee there is no
    owner-only DACL to write."""
    global _TOKEN_USER_SID
    if _TOKEN_USER_SID is not None:
        return _TOKEN_USER_SID
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.HANDLE))
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD))
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p,
                                           ctypes.POINTER(wintypes.LPWSTR))
    adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    k32.GetCurrentProcess.restype = wintypes.HANDLE  # pseudo-handle: never closed
    k32.LocalFree.argtypes = (ctypes.c_void_p,)
    k32.LocalFree.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    k32.CloseHandle.restype = wintypes.BOOL

    def fail(what: str) -> DaclError:
        return DaclError(ctypes.get_last_error(), what,
                         "cannot resolve the current user SID")

    htok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008,  # TOKEN_QUERY
                                ctypes.byref(htok)):
        raise fail("OpenProcessToken")
    try:
        need = wintypes.DWORD(0)
        adv.GetTokenInformation(htok, 1, None, 0,  # 1 == TokenUser: sizing call
                                ctypes.byref(need))
        if need.value == 0:
            raise fail("GetTokenInformation (sizing)")
        buf = ctypes.create_string_buffer(need.value)
        if not adv.GetTokenInformation(htok, 1, ctypes.cast(buf, ctypes.c_void_p),
                                       need.value, ctypes.byref(need)):
            raise fail("GetTokenInformation")
        # TOKEN_USER = { PSID user; DWORD attributes; }: the first member is
        # a pointer INTO the same returned buffer -- dereference it, the
        # buffer address itself is not the SID.
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents.value
        if not psid:
            raise fail("GetTokenInformation returned no SID")
        sid_str = wintypes.LPWSTR()
        if not adv.ConvertSidToStringSidW(psid, ctypes.byref(sid_str)) \
                or not sid_str.value:
            raise fail("ConvertSidToStringSidW")
        try:
            _TOKEN_USER_SID = sid_str.value
        finally:
            k32.LocalFree(sid_str)
        return _TOKEN_USER_SID
    finally:
        k32.CloseHandle(htok)


# 0x1F01FF is ntsecuritycon.FILE_ALL_ACCESS (specific rights, not the SDDL
# generic "FA"), so the stored ACE mask is byte-identical to what the
# retired pywin32 path produced and ssh's Windows permission checker sees
# exactly the same mask.
_SDDL_OWNER_ONLY_DACL = "D:P(A;;0x1F01FF;;;{sid})"


def _ctypes_protected_dacl(path: Path) -> None:
    """SetNamedSecurityInfoW via ctypes/advapi32: a PROTECTED DACL with
    exactly one ACE -- FILE_ALL_ACCESS for the current token user -- which
    cuts the ambient inherited ACL in the same operation. Raises DaclError
    carrying the Win32 error code on any failure (no ACL, no secrets)."""
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG))
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = \
        wintypes.BOOL
    adv.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL))
    adv.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    adv.SetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    adv.SetNamedSecurityInfoW.restype = wintypes.DWORD  # win32 error code
    k32.LocalFree.argtypes = (ctypes.c_void_p,)
    k32.LocalFree.restype = ctypes.c_void_p

    sddl = _SDDL_OWNER_ONLY_DACL.format(sid=_token_user_sid_string())
    psd = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(psd), None):  # 1 == SDDL_REVISION_1
        raise DaclError(ctypes.get_last_error(),
                        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                        str(path))
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        pdacl = ctypes.c_void_p()
        ok = adv.GetSecurityDescriptorDacl(psd, ctypes.byref(present),
                                           ctypes.byref(pdacl),
                                           ctypes.byref(defaulted))
        if not ok:
            raise DaclError(ctypes.get_last_error(),
                            "GetSecurityDescriptorDacl", str(path))
        if not present.value or not pdacl.value:
            # the API succeeded but the converted SD carries no DACL:
            # report that condition itself, not a stale last-error code
            raise DaclError(0, "converted SD carries no DACL", str(path))
        # SE_FILE_OBJECT == 1; DACL_SECURITY_INFORMATION (0x4) |
        # PROTECTED_DACL_SECURITY_INFORMATION (0x80000000): replace the
        # DACL and cut inheritance in one atomic call. NB: 0x10000000 is
        # UNPROTECTED_DACL_SECURITY_INFORMATION -- passing it silently
        # re-enables inheritance instead of cutting it.
        rc = adv.SetNamedSecurityInfoW(str(path.resolve()), 1,
                                       0x4 | 0x80000000,
                                       None, None, pdacl, None)
        if rc != 0:
            raise DaclError(rc, "SetNamedSecurityInfoW", str(path))
    finally:
        k32.LocalFree(psd)


_LOOSE_ACL_WARNED = False


def _warn_loose_dacl_once(reason: BaseException) -> None:
    """One warning per process no matter how many secret files degrade."""
    global _LOOSE_ACL_WARNED
    if _LOOSE_ACL_WARNED:
        return
    _LOOSE_ACL_WARNED = True
    print(f"wtssh: warning: owner-only DACL NOT applied ({reason}); secret "
          f"files fall back to chmod and keep their ambient ACL "
          f"(degraded by explicit opt-out WTSSH_ALLOW_LOOSE_ACL=1)",
          file=sys.stderr)


def apply_owner_only_dacl(path: Path) -> None:
    """Owner-only PROTECTED DACL on a file: single ACE, FILE_ALL_ACCESS,
    current user. Cuts the %TEMP% default ACL inheritance (which can grant
    read access beyond the owner); ssh/ssh-keygen also refuse group-readable
    key files, so this must be applied before they touch the file.

    Implemented via ctypes/advapi32 -- no pywin32 dependency. os.chmod is
    NOT an ACL mechanism on Windows (it only toggles the read-only flag),
    so a Windows failure here raises DaclError and callers fail closed:
    silently continuing turned the owner-only promise into a lie, and the
    askpass map is a plaintext password carrier. WTSSH_ALLOW_LOOSE_ACL=1 is
    the explicit acknowledged opt-out: chmod + a one-time warning. On POSIX
    chmod 0o600 IS the real mechanism and stays silent."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    try:
        _ctypes_protected_dacl(path)
    except OSError as e:
        if os.environ.get("WTSSH_ALLOW_LOOSE_ACL") == "1":
            _warn_loose_dacl_once(e)
            os.chmod(path, 0o600)
            return
        raise


def secure_mkkey(keydata: bytes, cleartext: bool = False) -> tuple[Path, Path]:
    """Materialize the key container in %TEMP% with an owner-only DACL.
    keydata is normally an ENCRYPTED ssh container, not a plaintext key;
    the session passphrase reaches ssh via askpass env and the key is
    decrypted only in ssh's memory. Wiped + removed by secure_rmtree; if
    the process is killed before that, the owner.pid marker lets the next
    connect's sweeper reclaim the dir (sweep_orphan_keydirs).

    cleartext=True is the single exception (agent load: ssh-add on Windows
    never consults SSH_ASKPASS, so a passphrase-protected container cannot
    be added headlessly -- the key is re-serialized unencrypted in Python
    first). The exposure window is one owner-only file, overwrite-wiped
    right after `ssh-add` returns; the caller documents the tradeoff."""
    tmpdir = Path(tempfile.mkdtemp(prefix="wtssh-key-"))
    keyfile = tmpdir / "key"
    # Tighten the DACL BEFORE any key material exists: the inherited %TEMP%
    # ACL (potentially readable beyond the owner) must not cover the write
    # window.
    keyfile.touch()
    try:
        apply_owner_only_dacl(keyfile)
    except BaseException:
        # nothing secret was written yet -- but the fail-closed die must
        # not strand an unprotected (and sweeper-invisible until aged)
        # keydir shell; best-effort removal, then surface the error
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    with open(keyfile, "wb") as f:
        f.write(keydata)
    try:
        (tmpdir / "owner.pid").write_text(str(os.getpid()),
                                          encoding="ascii")
    except OSError:
        pass  # sweeper falls back to the age-only rule for this dir
    return tmpdir, keyfile


def secure_wipe_tree(tmpdir: Path) -> tuple[bool, str]:
    """Overwrite every file under tmpdir (recursively), then remove the
    tree. Returns (False, error) instead of dying: the connect path wraps
    this to stay loud (secure_rmtree), while the stale-dir sweeper must not
    take down a live command over a leftover."""
    try:
        for root, _dirs, files in os.walk(tmpdir):
            for name in files:
                f = Path(root) / name
                length = f.stat().st_size
                with open(f, "r+b") as fh:
                    fh.write(b"\x00" * length)
        shutil.rmtree(tmpdir)
        return True, ""
    except OSError as e:
        return False, str(e)


def wipe_session_dirs(dirs: list[Path | None]) -> None:
    """Overwrite-wipe every session dir (decrypted containers, run dirs --
    the askpass map is a secret carrier with wipe priority equal to the
    containers). Never raises: failures are collected and warned so the
    ssh exit code always wins (R6)."""
    problems: list[tuple[Path, str]] = []
    for d in dirs:
        if d is None:
            continue
        ok, err = secure_wipe_tree(d)
        if not ok:
            problems.append((d, err))
    for d, err in problems:
        print(f"wtssh: warning: could not wipe {d}: {err} -- sensitive "
              f"material may remain; remove it manually", file=sys.stderr)


def secure_rmtree(tmpdir: Path) -> None:
    """secure_wipe_tree, but failure is fatal: die(5) so stranded key
    material is loud."""
    ok, err = secure_wipe_tree(tmpdir)
    if not ok:
        die(f"failed to wipe decrypted key dir {tmpdir}: {err} -- "
            f"key material may remain; remove it manually", 5)


def _pid_alive(pid: int) -> bool:
    """Best-effort liveness probe. NOT os.kill(pid, 0): on Windows that
    TERMINATES the target for any signal other than the CTRL_* events."""
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # explicit prototypes: a 64-bit HANDLE must not be truncated to c_int
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int,
                                ctypes.c_uint32]
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_ulong)]
    k32.GetExitCodeProcess.restype = ctypes.c_int
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.CloseHandle.restype = ctypes.c_int
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h:
        # ERROR_ACCESS_DENIED (5): the process exists but is not queryable.
        return ctypes.get_last_error() == 5
    try:
        code = ctypes.c_ulong()
        if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return True  # cannot tell: stay conservative
        return code.value == STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


def _sweep_orphan_dirs(root: Path, prefix: str, what: str,
                       max_age_s: int, dead_grace_s: int) -> None:
    """Shared orphan reclamation for marker-carrying session dirs (decrypted
    key containers, rendered-run dirs): a live owner is never touched."""
    now = time.time()
    try:
        candidates = [p for p in root.iterdir()
                      if p.name.startswith(prefix) and p.is_dir()]
    except OSError:
        return
    for d in candidates:
        try:
            age = now - d.stat().st_mtime
            marker = d / "owner.pid"
            if marker.exists():
                try:
                    pid = int(marker.read_text(encoding="ascii",
                                               errors="ignore").strip())
                except ValueError:
                    pid = 0
                if pid and _pid_alive(pid):
                    continue  # a live session owns this dir
                if age < dead_grace_s:
                    continue  # freshly exited; leave a grace window
            elif age < max_age_s:
                continue  # no marker: only reclaim clearly stale dirs
            ok, err = secure_wipe_tree(d)
            if not ok:
                print(f"wtssh: warning: could not wipe stale {what} dir "
                      f"{d}: {err}", file=sys.stderr)
        except OSError:
            continue


def sweep_orphan_keydirs(max_age_s: int = 24 * 3600,
                         dead_grace_s: int = 300) -> None:
    """Reclaim %TEMP%\\wtssh-key-* dirs whose owning connect process is
    gone (taskkill /F, a closed tab, power loss -- the finally in connect
    never ran). Dirs carry an owner.pid marker; a live owner is never
    touched, so running this while other tabs hold sessions is safe.
    Marker-less dirs (pre-marker leftovers) go only after max_age_s."""
    _sweep_orphan_dirs(Path(tempfile.gettempdir()), "wtssh-key-", "key",
                       max_age_s, dead_grace_s)


def sweep_orphan_rundirs(max_age_s: int = 24 * 3600,
                         dead_grace_s: int = 300) -> None:
    """Same reclamation for rendered-session dirs: a stale
    run dir carries the -F config (hostnames, usernames) and possibly the
    askpass map -- the secret carrier makes sweeping mandatory."""
    _sweep_orphan_dirs(run_root(), RUN_DIR_PREFIX, "run",
                       max_age_s, dead_grace_s)



def ssh_argv(p: dict) -> list[str]:
    """The argv to hand to `subprocess.run`.

    Tokens come back from `ssh_tokens` in their WRITTEN form (a value with
    spaces keeps its wrapping quotes, since ssh's own command line needs them
    when a shell builds it). subprocess builds a Windows command line itself,
    so the quotes must be stripped here -- leaving them in made ssh look for a
    file literally named `"C:\\dir with space\\key"` and silently skip the
    identity. argv[0] resolves to an absolute path (CWD excluded) so no
    spawn site can regress to CreateProcess's bare-name CWD search."""
    toks = entry_ssh_argv(p)
    if not toks or os.path.basename(toks[0]).lower().removesuffix(".exe") != "ssh":
        die(f"entry '{p['name']}' has a non-ssh commandline; cannot connect")
    toks[0] = resolve_bin(toks[0])
    return toks


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="wtssh", description=__doc__.splitlines()[0])
    ap.add_argument("--settings", help="override settings.json path "
                    "(default: auto-discovered; see $WTSSH_SETTINGS)")
    ap.add_argument("--secrets", help="override vault secrets dir "
                    "(default: %%LOCALAPPDATA%%/wtssh/secrets)")
    ap.add_argument("--keys", help="override standalone vault keys dir "
                    "(default: %%LOCALAPPDATA%%/wtssh/keys)")
    ap.add_argument("--agent-dir", help="override ssh-agent cache dir "
                    "(pub selectors + index; default: "
                    "%%LOCALAPPDATA%%/wtssh/agent)")
    ap.add_argument("--group", help="newTabMenu folder for ssh: entries "
                    "(default: $WTSSH_GROUP or 'ssh'); pass it BEFORE the "
                    "subcommand")
    ap.add_argument("--sftp-group", help="newTabMenu folder for sftp: "
                    "companions (default: $WTSSH_SFTP_GROUP or 'sftp'); "
                    "pass it BEFORE the subcommand")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("list", help="list ssh entries")
    sp.add_argument("--full", action="store_true", help="include full profile objects")
    sp.set_defaults(func=action_list)

    sp = sub.add_parser("show", help="dump one profile object")
    sp.add_argument("name")
    sp.set_defaults(func=action_show)

    sp = sub.add_parser("add", help="add an ssh entry")
    sp.add_argument("name")
    sp.add_argument("--user")
    sp.add_argument("--host", required=True)
    sp.add_argument("--port")
    sp.add_argument("--key", help="private key path, or 'wtv:KEYNAME' for a "
                    "standalone vault key ('wtssh key list')")
    sp.add_argument("--title", help="tab title override")
    sp.add_argument("--jump", help="entry name or user@host[:port]")
    sp.add_argument("--jump-mode", choices=("preserve", "expand"),
                    help="how to store --jump: 'preserve' (default) keeps a "
                         "book-entry alias verbatim, so ssh matches it "
                         "against the user config at runtime (import's "
                         "semantics); 'expand' resolves it to "
                         "user@host[:port] at write time")
    sp.add_argument("--extra", help="verbatim ssh options placed before the "
                    "destination (e.g. '-L 8080:127.0.0.1:80 "
                    "-o ServerAliveInterval=30')")
    sp.add_argument("--default", action="store_true", help="make it the default profile")
    sp.add_argument("--hidden", action="store_true",
                    help="keep the entry out of the WT ssh folder menu "
                         "(jump-host identity only; still --jump-able)")
    sp.add_argument("--sftp", action="store_true",
                    help="also create an 'sftp:<name>' FileZilla menu entry "
                         "in the sftp group (see --sftp-group; opens SFTP "
                         "via the FileZilla bridge; a jump chain tunnels "
                         "automatically)")
    sp.set_defaults(func=action_add)

    sp = sub.add_parser("edit", help="modify fields of an entry")
    sp.add_argument("name")
    sp.add_argument("--user")
    sp.add_argument("--host")
    sp.add_argument("--port")
    sp.add_argument("--key", help="private key path, or 'wtv:KEYNAME' for a "
                    "standalone vault key ('wtssh key list')")
    sp.add_argument("--title", help="tab title override ('' to clear)")
    sp.add_argument("--jump", help="entry name or user@host[:port]; 'none' clears")
    sp.add_argument("--jump-mode", choices=("preserve", "expand"),
                    help="how to store --jump ('preserve' is the default "
                         "and also clears an existing 'expand'; an explicit "
                         "'expand' without --jump also expands the stored "
                         "hop -- see `wtssh add --help`)")
    sp.add_argument("--extra", help="replace the entry's verbatim ssh options "
                    "(e.g. '-L 8080:127.0.0.1:80'); 'none' clears them")
    vis = sp.add_mutually_exclusive_group()
    vis.add_argument("--hidden", action="store_true",
                     help="remove from the WT ssh folder menu; the entry "
                          "stays in the book for --jump / connect")
    vis.add_argument("--visible", action="store_true",
                     help="put a hidden entry into the current group's menu")
    sftp = sp.add_mutually_exclusive_group()
    sftp.add_argument("--sftp", action="store_true",
                      help="create/update this entry's 'sftp:<name>' "
                           "FileZilla menu entry in the sftp group "
                           "(see --sftp-group; opens SFTP via the "
                           "FileZilla bridge; a jump chain tunnels "
                           "automatically)")
    sftp.add_argument("--no-sftp", action="store_true",
                      help="remove this entry's 'sftp:<name>' FileZilla "
                           "menu entry")
    sp.set_defaults(func=action_edit)

    sp = sub.add_parser("import", help="import hosts from an OpenSSH client "
                        "config (one entry per Host alias)")
    sp.add_argument("--ssh-config", default=str(Path.home() / ".ssh/config"),
                    help="config file to read (default: ~/.ssh/config)")
    sp.set_defaults(func=action_import)

    sp = sub.add_parser("rename", help="rename an entry (guid preserved)")
    sp.add_argument("old")
    sp.add_argument("new")
    sp.set_defaults(func=action_rename)

    sp = sub.add_parser("remove", help="delete an entry")
    sp.add_argument("name")
    sp.add_argument("--force", action="store_true",
                    help="delete even if other entries --jump this name")
    sp.set_defaults(func=action_remove)

    sp = sub.add_parser("move", help="reorder within the current group")
    sp.add_argument("name")
    sp.add_argument("--top", action="store_true")
    sp.add_argument("--bottom", action="store_true")
    sp.add_argument("--before")
    sp.add_argument("--after")
    sp.set_defaults(func=action_move)

    sp = sub.add_parser("guid", help="print resolved GUID")
    sp.add_argument("name")
    sp.set_defaults(func=action_guid)

    sp = sub.add_parser("print", help="render an entry: the exact ssh "
                        "command (--cmd) or a hop/identity plan (--plan, "
                        "default; no secrets)")
    sp.add_argument("name")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--plan", action="store_true",
                   help="hop/target structure as JSON (default)")
    g.add_argument("--cmd", action="store_true",
                   help="the embedded ssh command line")
    sp.set_defaults(func=action_print)

    sp = sub.add_parser("doctor", help="advisory self-checks (names, key "
                        "refs, hop resolution, ssh version); findings as "
                        "JSON, exit code always 0")
    sp.add_argument("name", nargs="?", help="check one entry (default: all)")
    sp.set_defaults(func=action_doctor)

    sp = sub.add_parser("get-default", help="print current default profile")
    sp.set_defaults(func=action_get_default)

    sp = sub.add_parser("set-default", help="set default profile (ssh entries only)")
    sp.add_argument("name")
    sp.set_defaults(func=action_set_default)

    sp = sub.add_parser("secret", help="manage vault-encrypted passphrases")
    secret_sub = sp.add_subparsers(dest="secret_cmd", required=True)
    ssp = secret_sub.add_parser("set", help="store passphrase for an entry "
                                "(hidden console prompt, or native dialog "
                                "when stdin is piped)")
    ssp.add_argument("name")
    ssp.set_defaults(func=action_secret_set)
    ssp = secret_sub.add_parser("remove", help="delete stored passphrase")
    ssp.add_argument("name")
    ssp.set_defaults(func=action_secret_remove)
    ssp = secret_sub.add_parser("list", help="list entries with stored passphrases")
    ssp.set_defaults(func=action_secret_list)

    sp = sub.add_parser("key", help="manage standalone vault keys")
    key_sub = sp.add_subparsers(dest="key_cmd", required=True)
    ksp = key_sub.add_parser("import", help="seal a private key file into the "
                              "vault as a standalone KEYNAME (no host entry "
                              "needed; encrypted keys prompt via native "
                              "dialog, never stdin)")
    ksp.add_argument("name", help="standalone key name (KEYNAME); an entry of "
                     "the same name, if any, is also re-pointed at it")
    ksp.add_argument("keyfile", help="path to the private key file")
    ksp.add_argument("--move", action="store_true",
                     help="after sealing, overwrite and delete the source "
                          "key file (the vault copy supersedes it)")
    ksp.set_defaults(func=action_key_import)
    ksp = key_sub.add_parser("list", help="list standalone keys and the "
                              "entries referencing them (no PIN)")
    ksp.set_defaults(func=action_key_list)
    ksp = key_sub.add_parser("rename", help="rename a standalone key, "
                              "re-pointing every referencing entry")
    ksp.add_argument("old")
    ksp.add_argument("new")
    ksp.set_defaults(func=action_key_rename)
    ksp = key_sub.add_parser("export", help="export a standalone key back to "
                             "a passphrase-protected file (CNG PIN + "
                             "new-passphrase dialog; the key is "
                             "re-encrypted, never written in the clear)")
    ksp.add_argument("name", help="standalone key name to export")
    ksp.add_argument("outfile", help="destination path for the exported "
                     "passphrase-protected key file")
    ksp.set_defaults(func=action_key_export)
    ksp = key_sub.add_parser("remove", help="delete a standalone key "
                              "(refused while an entry references it)")
    ksp.add_argument("name")
    ksp.add_argument("--force", action="store_true",
                     help="also drop the -i references from entries that use "
                          "the key, leaving them without that identity")
    ksp.set_defaults(func=action_key_remove)

    sp = sub.add_parser("agent", help="cache vault keys in ssh-agent: one "
                        "TPM PIN loads them, then connects run PIN-free "
                        "until the TTL expires")
    agent_sub = sp.add_subparsers(dest="agent_cmd", required=True)
    asp = agent_sub.add_parser("load", help="unwrap vault keys (ONE PIN for "
                               "the batch) and cache them in ssh-agent for "
                               "--ttl (default: $WTSSH_AGENT_TTL or 8h)")
    asp.add_argument("keys", nargs="*", help="vault keys to load "
                     "(default: all standalone keys)")
    asp.add_argument("--ttl", help="cache lifetime: seconds or s/m/h/d/w "
                     "suffixes (e.g. 8h, 90m)")
    asp.set_defaults(func=action_agent_load)
    asp = agent_sub.add_parser("unload", help="drop wtssh-cached keys from "
                               "ssh-agent (default: our live-tracked keys "
                               "only, never your hand-added ones)")
    asp.add_argument("keys", nargs="*", help="cached keys to drop "
                     "(default: all wtssh-tracked live keys)")
    asp.add_argument("--all", action="store_true",
                     help="ssh-add -D: drop EVERYTHING in the agent "
                          "(including your hand-added keys) and clear "
                          "the wtssh index")
    asp.set_defaults(func=action_agent_unload)
    asp = agent_sub.add_parser("status", help="agent + cache inventory "
                               "(read-only, no PIN)")
    asp.set_defaults(func=action_agent_status)

    def _filezilla_parser(name: str, help_text: str):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("name", help="host-book entry to open in FileZilla")
        sp.add_argument("--keyfile",
                        help="bind this plaintext key file to the FileZilla "
                             "site (needed once for entries on wtv: vault "
                             "keys, which FileZilla cannot read)")
        sp.add_argument("--no-open", action="store_true",
                        help="sync the FileZilla site only; do not launch")
        sp.add_argument("--remove-site", action="store_true",
                        help="remove the entry's site from the wtssh folder "
                             "in FileZilla's Site Manager instead of syncing")
        sp.add_argument("--tunnel", nargs="?", const="yes", default=False,
                        choices=("yes", "auto"),
                        help="jump-host mode: pick a random free high port "
                             "and run the rendered jump chain as a local "
                             "SOCKS5 proxy whose dials originate at the "
                             "LAST HOP (same vantage as -J), keep the site "
                             "at the entry's real host/port, point "
                             "FileZilla's generic proxy at the listener "
                             "(previous proxy settings restored when the "
                             "launched FileZilla instance exits -- which "
                             "also ends the proxy process and wipes the "
                             "session key), and export the entry's vault "
                             "key (if any) as a session key file (random "
                             "passphrase; shown on a terminal, clipboard-"
                             "only when stdout is piped). A rendered chain "
                             "with a vault key costs ONE PIN (export + "
                             "chain unlock in a single batch gesture); "
                             "chains that cannot render fall back to a "
                             "child connect with its own PIN (legacy -L "
                             "shape, site rewritten to 127.0.0.1:<port>). "
                             "'--tunnel auto' (the sftp:<name> menu "
                             "entry's mode) tunnels only when the entry "
                             "has a jump -- the mode exclusions above then "
                             "fire only on entries that really tunnel")
        sp.add_argument("--filezilla",
                        help="path to filezilla.exe (default: "
                             "$WTSSH_FILEZILLA, then the standard install "
                             "dirs, then PATH)")
        sp.add_argument("--to-clipboard", action="store_true",
                        help="copy the entry's stored login password to the "
                             "clipboard for pasting into FileZilla "
                             "(explicit opt-in: pops a native Yes/No "
                             "confirmation naming the entry, then a TPM PIN; "
                             "the password is never printed to "
                             "stdout/stderr/JSON/logs; direct-only, needs a "
                             "stored secret, refuses with "
                             "--no-open/--remove-site/--keyfile/--tunnel)")
        sp.set_defaults(func=action_filezilla)
        return sp

    _filezilla_parser("filezilla",
                      "open a host-book entry in FileZilla (Site Manager "
                      "sync + `filezilla -c` direct connect)")
    _filezilla_parser("fz", "alias of filezilla")

    def _connect_parser(name: str, help_text: str):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("name")
        sp.add_argument("--tunnel-forward",
                        metavar="LOCAL_PORT:REMOTE_HOST:REMOTE_PORT",
                        help="pure port-forward mode: no remote shell (-N "
                             "implied), e.g. 2222:127.0.0.1:22 forwards "
                             "local port 2222 to REMOTE_PORT as seen from "
                             "the target's side (rendered jump chain still "
                             "applies)")
        sp.add_argument("--no-askpass", action="store_true",
                        help="render the chain but do not register the "
                             "askpass dispatcher: ssh prompts for key "
                             "passphrases on the terminal instead "
                             "(explicit opt-out)")
        sp.add_argument("--no-agent", action="store_true",
                        help="ignore keys cached in ssh-agent even when "
                             "they cover this entry (force the TPM PIN "
                             "path; $WTSSH_NO_AGENT=1 does the same)")
        sp.add_argument("extra", nargs="*", help=argparse.SUPPRESS,
                        metavar="-- ssh ARGS (from routed commandlines)")
        sp.set_defaults(func=action_connect)
        return sp

    _connect_parser("connect", "connect to an entry (vault unwrap + ssh; a "
                    "renderable jump chain is rendered with per-hop keys)")
    _connect_parser("open", "alias of connect")

    sp = sub.add_parser("run", help="run a remote command on an entry, "
                        "ssh-style: stdout is the remote output, wtssh's "
                        "own output goes to stderr, the exit code is ssh's "
                        "(may also be invoked bare as `wtssh NAME ...`)")
    sp.add_argument("name")
    sp.add_argument("--tunnel-forward",
                    metavar="LOCAL_PORT:REMOTE_HOST:REMOTE_PORT",
                    help="pure port-forward mode: no remote shell (-N "
                         "implied); cannot be combined with a command")
    sp.add_argument("--no-askpass", action="store_true",
                    help="do not register the askpass dispatcher: ssh "
                         "prompts for key passphrases on the terminal "
                         "instead (explicit opt-out)")
    sp.add_argument("--no-agent", action="store_true",
                    help="ignore keys cached in ssh-agent even when "
                         "they cover this entry (force the TPM PIN "
                         "path; $WTSSH_NO_AGENT=1 does the same)")
    sp.add_argument("command", nargs=argparse.REMAINDER,
                    help="remote command appended after the destination "
                         "(`run NAME -- cmd...` also accepted; empty "
                         "means an interactive login, like ssh)")
    sp.set_defaults(func=action_connect)

    sp = sub.add_parser("__askpass", help=argparse.SUPPRESS)
    sp.add_argument("prompt", nargs="*", help=argparse.SUPPRESS)
    sp.set_defaults(func=action_askpass)

    sp = sub.add_parser("vault", help="manage the TPM-backed key vault")
    vault_sub = sp.add_subparsers(dest="vault_cmd", required=True)
    vsp = vault_sub.add_parser("init", help="create the TPM vault key "
                               "(dialogs: set PIN, then a consent self-test)")
    vsp.set_defaults(func=action_vault_init)
    vsp = vault_sub.add_parser("status", help="vault key and blob inventory (no gesture)")
    vsp.set_defaults(func=action_vault_status)
    vsp = vault_sub.add_parser("remove", help="delete the TPM vault key")
    vsp.set_defaults(func=action_vault_remove)
    return ap



# Keep in sync with build_parser(): every top-level subcommand name.
# _bare_run_rewrite consults this (never argparse's private _actions), and
# test_subcommands_set_matches_parser fails the suite if the two drift.
SUBCOMMANDS = frozenset((
    "list", "show", "add", "edit", "import", "rename", "remove", "move",
    "guid", "print", "doctor", "get-default", "set-default", "secret",
    "key", "filezilla", "fz", "connect", "open", "run", "__askpass",
    "vault", "agent",
))

_BARE_RUN_GLOBALS = frozenset(("--settings", "--secrets", "--keys",
                               "--agent-dir", "--group", "--sftp-group"))


def _bare_run_rewrite(ap, argv):
    """Native-style bare form: `wtssh NAME [cmd...]` → `wtssh run NAME
    [cmd...]`. Only fires when the first non-global token is neither a flag
    nor a known subcommand name -- subcommands always win (an entry
    literally named e.g. `list` still needs `run list ...`). Every global
    takes exactly one value (`--opt v` or `--opt=v`), so globals are
    skipped wholesale; anything else starting with `-` (e.g. `-h`) is
    left alone for argparse to handle. `ap` is accepted for signature
    stability but deliberately unused: the set above is the single
    source (no argparse-private introspection in prod code)."""
    known = SUBCOMMANDS
    i = 0
    while i < len(argv):
        base = argv[i].split("=", 1)[0]
        if base not in _BARE_RUN_GLOBALS:
            break
        i += 1 if "=" in argv[i] else 2
    if i < len(argv) and not argv[i].startswith("-") \
            and argv[i] not in known:
        return argv[:i] + ["run"] + argv[i:]
    return argv


def main(argv=None):
    global GROUP, SFTP_GROUP, SETTINGS
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    # Keep the CWD off this process's executable search path before anything
    # can spawn: the flag governs CreateProcess's bare-name resolution for
    # every subprocess below AND the child tree (ssh's ProxyCommand spawns,
    # cmd.exe), and shutil.which() consults the same WinAPI since 3.12.
    # Presence is what matters; an existing value is left alone.
    os.environ.setdefault("NoDefaultCurrentDirectoryInExePath", "1")
    ap = build_parser()
    raw = list(sys.argv[1:]) if argv is None else list(argv)
    args = ap.parse_args(_bare_run_rewrite(ap, raw))
    # --group / --sftp-group win over $WTSSH_GROUP / $WTSSH_SFTP_GROUP,
    # which defaulted at import time
    if args.group is not None:
        if not args.group.strip():
            die("--group must not be empty")
        GROUP = args.group.strip()
    if getattr(args, "sftp_group", None) is not None:
        if not args.sftp_group.strip():
            die("--sftp-group must not be empty")
        SFTP_GROUP = args.sftp_group.strip()
    if getattr(args, "settings", None):
        SETTINGS = Path(args.settings).resolve()
    if getattr(args, "secrets", None):
        global SECRETS_DIR
        SECRETS_DIR = Path(args.secrets).resolve()
    if getattr(args, "keys", None):
        global KEYS_DIR
        KEYS_DIR = Path(args.keys).resolve()
    if getattr(args, "agent_dir", None):
        global AGENT_DIR
        AGENT_DIR = Path(args.agent_dir).resolve()
    # Drill-mode visibility: WTSSH_KEYS/WTSSH_SECRETS stick in a shell
    # session long after the drill ended, and a vault-reporting command then
    # silently describes the sandbox instead of the real vault. One stderr
    # line on the read paths where that mismatch matters.
    if (os.environ.get("WTSSH_KEYS") or os.environ.get("WTSSH_SECRETS")) \
            and _reports_vault(args):
        print("wtssh: note: WTSSH_KEYS/WTSSH_SECRETS are set (drill mode); "
              "this report describes the sandbox, not the real vault",
              file=sys.stderr)
    if os.environ.get("WTSSH_AGENT_DIR") and args.cmd == "agent":
        if getattr(args, "agent_cmd", None) == "status":
            print("wtssh: note: WTSSH_AGENT_DIR is set (drill mode); "
                  "this report describes the sandbox, not the real "
                  "agent cache", file=sys.stderr)
        else:
            # load/unload: the INDEX is sandboxed, but ssh-add always
            # talks to the real agent -- say so before any mutation.
            print("wtssh: note: WTSSH_AGENT_DIR is set (drill mode); the "
                  "index is sandboxed but ssh-add still talks to the "
                  "REAL agent", file=sys.stderr)
    try:
        args.func(args)
    except DaclError as e:
        # fail-closed: no secret was materialized on an unprotectable
        # location. Every flow's own finally has already wiped its session
        # dirs by the time the error surfaces here; turn it into a clean
        # remediation message instead of a bare traceback.
        die(f"cannot apply the owner-only DACL ({e}); session secrets "
            f"were NOT written -- relocate TMP/WTSSH_RUN_DIR to an "
            f"ACL-capable volume, or set WTSSH_ALLOW_LOOSE_ACL=1 to "
            f"proceed unprotected", 4)


def _reports_vault(args) -> bool:
    """True for the commands whose output describes vault state (list / key
    list / secret list / vault status)."""
    if args.cmd == "list":
        return True
    if args.cmd == "key" and getattr(args, "key_cmd", None) == "list":
        return True
    if args.cmd == "secret" and getattr(args, "secret_cmd", None) == "list":
        return True
    return args.cmd == "vault" and getattr(args, "vault_cmd", None) == "status"



if __name__ == "__main__":
    main()
