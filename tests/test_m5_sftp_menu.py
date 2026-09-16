"""Offline drill tests for the sftp:<name> FileZilla menu-entry companions
(no vault, no real ssh, no writes to the live settings / site list):

  1. add --sftp pins the companion in the sftp group (not the ssh group);
     the commandline is the canonical `sftp_line` shape; `list` flags the
     ssh row with sftp:true + sftpGroup and no companion row leaks into
     any enumeration.
  2. edit --sftp is idempotent (re-run on an existing canonical companion
     reports changed:false); --no-sftp removes it; a second --no-sftp is a
     clean no-op.
  3. rename / remove / move propagate: the companion follows its entry
     (rename/remove) and stays in the sftp group across ssh-group moves;
     the JSON reports rewroteSftp/removedSftp. `--sftp-group` equal to
     `--group` restores the adjacent-in-same-folder form.
  4. a legacy cmd-unsafe entry name refuses edit --sftp with the rename
     guidance (the routed-line red line also guards companion lines).
  5. resolve_tunnel_mode truth table (yes / legacy True / auto+jump /
     auto+no-jump / absent).
  6. doctor reports sftp-orphan / sftp-cmd-unsafe / sftp-bad-line /
     sftp-default findings for hand-mangled companions; single-entry mode
     scopes the check.
  7. filezilla --tunnel auto on a jump-free entry runs the plain sync path
     (tunnelAuto "direct", no tunnel block, --no-open legal); a jump-free
     vault entry still keeps --no-open on the ask fallback (no session-key
     export without a launch). On a jumped entry auto resolves to tunnel
     and --no-open is refused; explicit --tunnel still refuses --no-open
     on a jump-free entry.
  8. edit --no-sftp removes an orphan companion (dead ssh name) without
     hand-editing settings.json; creating one for a dead name still dies.
  9. rename into an existing companion dies before any write (no
     half-state).
  10. a shim path containing spaces still matches the canonical shape.

Run:  python tests/test_m5_sftp_menu.py
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

TMP = Path(tempfile.mkdtemp(prefix="wtssh-m5-test-"))
FAILURES: list[str] = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


def setup_env():
    os.environ["WTSSH_SHIM_DIR"] = str(TMP / "shim")
    os.environ["WTSSH_AUDIT_DIR"] = str(TMP / "log")
    os.environ["WTSSH_FZ_SITEMANAGER"] = str(TMP / "sitemanager.xml")
    wtssh.SETTINGS = TMP / "settings.json"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.KEYS_DIR = TMP / "keys"
    for d in (wtssh.SECRETS_DIR, wtssh.KEYS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    (TMP / "sitemanager.xml").write_text(
        '<?xml version="1.0"?><FileZilla3><Servers /></FileZilla3>',
        encoding="utf-8")


def write_settings(entries, default=None):
    doc = {"profiles": {"list": entries}}
    if default is not None:
        doc["defaultProfile"] = default
    wtssh.SETTINGS.write_text(json.dumps(doc), encoding="utf-8")


def add_args(**kw):
    base = dict(name="", user=None, host=None, port=None, key=None,
                title=None, jump=None, jump_mode=None, extra=None,
                default=False, hidden=False, sftp=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def edit_args(**kw):
    base = dict(name="", user=None, host=None, port=None, key=None,
                title=None, jump=None, jump_mode=None, extra=None,
                hidden=False, visible=False, sftp=False, no_sftp=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def fz_args(**kw):
    base = dict(name="", keyfile=None, no_open=False, remove_site=False,
                tunnel=False, filezilla=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def run(action, args):
    """Run an action with captured streams; returns (out, err, exit-code)."""
    out, err = io.StringIO(), io.StringIO()
    code = None
    try:
        with redirect_stdout(out), redirect_stderr(err):
            action(args)
    except SystemExit as e:
        code = e.code
    return out.getvalue(), err.getvalue(), code


def fresh_entry(name, host, guid_suffix):
    return {"name": f"ssh:{name}",
            "guid": f"{{dddddddd-0000-0000-0000-{guid_suffix}}}",
            "commandline": f"ssh u@{host}"}


def folder_guids(folder):
    return [e.get("profile") for e in (folder or {}).get("entries", [])]


def test_add_sftp():
    print("[add --sftp: companion in sftp group, list flags it]")
    write_settings([])
    out, err, code = run(wtssh.action_add,
                         add_args(name="alpha", host="a.example", sftp=True))
    doc = json.loads(out)
    check("add ok with sftp flag", code is None and doc.get("sftp") is True,
          out + err)
    check("add reports sftpGroup", doc.get("sftpGroup") == "sftp", out)
    data = wtssh.load()
    comp = wtssh.find_sftp_profile(data, "alpha")
    ssh = wtssh.find_profile(data, "alpha")
    check("companion in profiles.list", comp is not None)
    check("canonical commandline", comp is not None
          and comp["commandline"].endswith(" filezilla alpha --tunnel auto"))
    check("sftp_profile_ok", comp is not None
          and wtssh.sftp_profile_ok(comp, "alpha"))
    ssh_guids = folder_guids(wtssh.get_folder(data))
    sftp_folder = wtssh.get_sftp_folder(data)
    sftp_guids = folder_guids(sftp_folder)
    check("ssh entry in ssh group", ssh is not None and ssh["guid"] in ssh_guids)
    check("companion not in ssh group",
          comp is not None and comp["guid"] not in ssh_guids, str(ssh_guids))
    check("sftp folder named sftp",
          sftp_folder is not None and sftp_folder.get("name") == "sftp")
    check("companion in sftp group",
          comp is not None and comp["guid"] in sftp_guids, str(sftp_guids))
    out, err, code = run(wtssh.action_list,
                         types.SimpleNamespace(group=None, full=False))
    payload = json.loads(out)
    rows = payload["groups"]["ssh"]
    row = next(r for r in rows if r["name"] == "alpha")
    check("list row carries sftp:true", row.get("sftp") is True)
    check("list row carries sftpGroup", row.get("sftpGroup") == "sftp", out)
    check("sftp folder not listed as an ssh group",
          "sftp" not in payload["groups"], out)
    everything = rows + payload["ungrouped"] + payload["hidden"]
    check("no companion row leaked",
          all(not str(r["name"]).startswith("sftp") for r in everything)
          and all(r["name"] != ":alpha" for r in everything),
          out)


def test_edit_sftp_idempotent():
    print("[edit --sftp idempotence / --no-sftp]")
    out, err, code = run(wtssh.action_edit, edit_args(name="alpha", sftp=True))
    doc = json.loads(out)
    check("re-run on existing companion: changed false",
          code is None and doc.get("changed") is False
          and doc.get("sftp") is True, out + err)
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="alpha", no_sftp=True))
    doc = json.loads(out)
    check("no-sftp removes", code is None and doc.get("sftp") is False,
          out + err)
    check("companion gone",
          wtssh.find_sftp_profile(wtssh.load(), "alpha") is None)
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="alpha", no_sftp=True))
    doc = json.loads(out)
    check("second no-sftp is a no-op",
          code is None and doc.get("changed") is False, out + err)
    # combined edits: field change + companion change in one call
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="alpha", host="a2.example",
                                   sftp=True))
    doc = json.loads(out)
    check("combined edit creates companion",
          code is None and doc.get("sftp") is True, out + err)
    check("combined edit kept the companion canonical",
          wtssh.sftp_profile_ok(
              wtssh.find_sftp_profile(wtssh.load(), "alpha"), "alpha"))
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="alpha", hidden=True, sftp=True))
    doc = json.loads(out)
    check("hidden+sftp combined edit accepted",
          code is None and doc.get("hidden") is True
          and doc.get("sftp") is True, out + err)
    check("companion still there after hidden+sftp",
          wtssh.find_sftp_profile(wtssh.load(), "alpha") is not None)
    run(wtssh.action_edit, edit_args(name="alpha", visible=True))
    run(wtssh.action_edit, edit_args(name="alpha", no_sftp=True))


def test_rename_remove_move_propagate():
    print("[rename/remove/move propagate]")
    run(wtssh.action_add, add_args(name="beta", host="b.example", sftp=True))
    comp0 = wtssh.find_sftp_profile(wtssh.load(), "beta")
    out, err, code = run(wtssh.action_rename,
                         types.SimpleNamespace(old="beta", new="gamma"))
    doc = json.loads(out)
    check("rename reports rewroteSftp",
          code is None and doc.get("rewroteSftp") is True, out + err)
    data = wtssh.load()
    comp = wtssh.find_sftp_profile(data, "gamma")
    check("companion renamed, guid kept",
          comp is not None and comp["guid"] == comp0["guid"])
    check("companion line retargeted", comp is not None
          and comp["commandline"].endswith(" filezilla gamma --tunnel auto"))
    out, err, code = run(wtssh.action_move,
                         types.SimpleNamespace(name="gamma", top=True,
                                               bottom=False, before=None,
                                               after=None))
    check("move ok", code is None, out + err)
    data = wtssh.load()
    ssh = wtssh.find_profile(data, "gamma")
    ssh_guids = folder_guids(wtssh.get_folder(data))
    sftp_guids = folder_guids(wtssh.get_sftp_folder(data))
    check("move does not drag companion into ssh group",
          comp["guid"] not in ssh_guids, str(ssh_guids))
    check("companion stays in sftp group after move",
          comp["guid"] in sftp_guids, str(sftp_guids))
    check("ssh entry moved to top of ssh group",
          ssh is not None and ssh_guids and ssh_guids[0] == ssh["guid"],
          str(ssh_guids))
    out, err, code = run(wtssh.action_remove,
                         types.SimpleNamespace(name="gamma", force=False))
    doc = json.loads(out)
    check("remove reports removedSftp",
          code is None and doc.get("removedSftp") is True, out + err)
    data = wtssh.load()
    check("companion removed with its entry",
          wtssh.find_sftp_profile(data, "gamma") is None
          and wtssh.find_profile(data, "gamma") is None)


def test_cmd_unsafe_refused():
    print("[legacy cmd-unsafe name refuses edit --sftp]")
    write_settings([{"name": "ssh:bad&x",
                     "guid": "{bbbbbbbb-0000-0000-0000-000000000001}",
                     "commandline": "ssh u@h.example"}])
    out, err, code = run(wtssh.action_edit, edit_args(name="bad&x", sftp=True))
    check("edit --sftp dies on cmd-unsafe name", code == 1
          and "cmd metacharacters" in err, f"code={code} err={err}")
    check("refusal names the escape hatch", "rename" in err, err)


def test_resolve_tunnel_mode():
    print("[resolve_tunnel_mode truth table]")
    check("absent -> direct",
          wtssh.resolve_tunnel_mode(False, "j") == "direct")
    check("yes -> tunnel", wtssh.resolve_tunnel_mode("yes", None) == "tunnel")
    check("legacy True -> tunnel",
          wtssh.resolve_tunnel_mode(True, None) == "tunnel")
    check("auto + jump -> tunnel",
          wtssh.resolve_tunnel_mode("auto", "j") == "tunnel")
    check("auto without jump -> direct",
          wtssh.resolve_tunnel_mode("auto", None) == "direct")


def test_doctor_findings():
    print("[doctor: companion findings]")
    shim_line = str(wtssh.shim_path())
    entries = [
        fresh_entry("alpha", "a.example", "000000000003"),
        # canonical shape, but the ssh entry is gone -> orphan
        {"name": "sftp:ghost",
         "guid": "{cccccccc-0000-0000-0000-000000000001}",
         "commandline": f"{shim_line} filezilla ghost --tunnel auto"},
        # existing ssh entry, non-canonical payload -> bad line
        {"name": "sftp:alpha",
         "guid": "{cccccccc-0000-0000-0000-000000000002}",
         "commandline": "notepad.exe"},
    ]
    write_settings(entries)
    out, err, code = run(wtssh.action_doctor,
                         types.SimpleNamespace(name=None))
    rep = json.loads(out)["findings"]
    codes = {k: [f["check"] for f in v] for k, v in rep.items()}
    check("orphan flagged",
          "sftp-orphan" in codes.get("sftp:ghost", []), out)
    check("orphan not flagged bad-line",
          "sftp-bad-line" not in codes.get("sftp:ghost", []), out)
    check("bad line flagged",
          "sftp-bad-line" in codes.get("sftp:alpha", []), out)
    check("bad line not flagged orphan",
          "sftp-orphan" not in codes.get("sftp:alpha", []), out)
    write_settings(entries, default="{cccccccc-0000-0000-0000-000000000001}")
    out, err, code = run(wtssh.action_doctor,
                         types.SimpleNamespace(name=None))
    rep = json.loads(out)["findings"]
    check("default flagged",
          "sftp-default" in [f["check"] for f in rep.get("sftp:ghost", [])],
          out)
    write_settings(entries)
    out, err, code = run(wtssh.action_doctor,
                         types.SimpleNamespace(name="alpha"))
    rep = json.loads(out)["findings"]
    check("single-entry mode scopes companions",
          "sftp:ghost" not in rep and "sftp:alpha" in rep, out)
    # a shape-clean companion whose ssh name carries cmd metacharacters
    # (hand-edit only) is flagged as cmd-unsafe, not bad-line
    entries2 = [
        {"name": "ssh:bad&x",
         "guid": "{eeeeeeee-0000-0000-0000-000000000003}",
         "commandline": "ssh u@h.example"},
        {"name": "sftp:bad&x",
         "guid": "{eeeeeeee-0000-0000-0000-000000000004}",
         "commandline": f"{shim_line} filezilla bad&x --tunnel auto"},
    ]
    write_settings(entries2)
    out, err, code = run(wtssh.action_doctor,
                         types.SimpleNamespace(name=None))
    rep = json.loads(out)["findings"]
    codes = [f["check"] for f in rep.get("sftp:bad&x", [])]
    check("cmd-unsafe companion flagged", "sftp-cmd-unsafe" in codes, out)
    check("shape-clean unsafe companion not flagged bad-line",
          "sftp-bad-line" not in codes, out)


def test_orphan_companion_removal():
    print("[edit --no-sftp removes an orphan companion]")
    write_settings([
        {"name": "sftp:ghost",
         "guid": "{eeeeeeee-0000-0000-0000-000000000005}",
         "commandline": f"{wtssh.shim_path()} filezilla ghost --tunnel auto"},
    ])
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="ghost", no_sftp=True))
    doc = json.loads(out)
    check("orphan companion removed",
          code is None and doc.get("orphan") is True
          and doc.get("changed") is True, out + err)
    check("companion gone from settings",
          wtssh.find_sftp_profile(wtssh.load(), "ghost") is None)
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="ghost", no_sftp=True))
    doc = json.loads(out)
    check("dead name without companion: no-op",
          code is None and doc.get("changed") is False, out + err)
    out, err, code = run(wtssh.action_edit, edit_args(name="ghost", sftp=True))
    check("creating for a dead name still dies", code == 1
          and "no ssh entry" in err, f"code={code} err={err}")


def test_rename_collision_no_halfstate():
    print("[rename into an existing companion dies cleanly]")
    a_comp = f"{wtssh.shim_path()} filezilla a1 --tunnel auto"
    b_comp = f"{wtssh.shim_path()} filezilla b1 --tunnel auto"
    # no ssh:b1: the ssh-name pre-check must pass so the rename actually
    # reaches the companion-collision guard (only a hand-planted sftp:b1)
    write_settings([
        fresh_entry("a1", "a1.example", "000000000006"),
        {"name": "sftp:a1", "guid": "{eeeeeeee-0000-0000-0000-000000000006}",
         "commandline": a_comp},
        {"name": "sftp:b1", "guid": "{eeeeeeee-0000-0000-0000-000000000007}",
         "commandline": b_comp},
    ])
    out, err, code = run(wtssh.action_rename,
                         types.SimpleNamespace(old="a1", new="b1"))
    check("rename dies on companion collision", code == 1
          and "SFTP menu entry" in err, f"code={code} err={err}")
    data = wtssh.load()
    check("no half-state: entry and companions intact",
          wtssh.find_profile(data, "a1") is not None
          and wtssh.find_profile(data, "b1") is None
          and wtssh.find_sftp_profile(data, "a1")["commandline"] == a_comp
          and wtssh.find_sftp_profile(data, "b1")["commandline"] == b_comp)


def test_spaced_shim_path():
    print("[shim path with spaces still matches the canonical shape]")
    spaced = TMP / "shim dir with spaces"
    spaced.mkdir(exist_ok=True)
    old = os.environ.get("WTSSH_SHIM_DIR")
    os.environ["WTSSH_SHIM_DIR"] = str(spaced)
    try:
        line = wtssh.sftp_line("alpha")
        check("sftp_line quotes the spaced shim",
              '"' in line and line.endswith(" filezilla alpha --tunnel auto"))
        comp = {"name": "sftp:alpha",
                "guid": "{eeeeeeee-0000-0000-0000-000000000008}",
                "commandline": line}
        check("sftp_profile_ok on spaced path",
              wtssh.sftp_profile_ok(comp, "alpha"))
    finally:
        if old is None:
            os.environ.pop("WTSSH_SHIM_DIR", None)
        else:
            os.environ["WTSSH_SHIM_DIR"] = old


def test_filezilla_auto_modes():
    print("[filezilla --tunnel auto: direct path + exclusions]")
    write_settings([fresh_entry("alpha", "a.example", "000000000004")])
    out, err, code = run(wtssh.action_filezilla,
                         fz_args(name="alpha", no_open=True, tunnel="auto"))
    doc = json.loads(out)
    check("auto direct: sync ok", code is None, out + err)
    check("auto direct: no tunnel block", "tunnel" not in doc, out)
    check("auto direct reported", doc.get("tunnelAuto") == "direct", out)
    out, err, code = run(wtssh.action_filezilla,
                         fz_args(name="alpha", no_open=True, tunnel="yes"))
    check("explicit --tunnel still refuses --no-open", code == 1
          and "drop --no-open" in err, f"code={code} err={err}")
    write_settings([
        {"name": "ssh:j", "guid": "{dddddddd-0000-0000-0000-000000000002}",
         "commandline": "ssh u@j.example", "hidden": True},
        {"name": "ssh:t", "guid": "{dddddddd-0000-0000-0000-000000000003}",
         "commandline": "ssh -J j u@t.example"},
    ])
    out, err, code = run(wtssh.action_filezilla,
                         fz_args(name="t", no_open=True, tunnel="auto"))
    check("auto tunnel refuses --no-open", code == 1
          and "drop --no-open" in err, f"code={code} err={err}")


def test_sftp_group_override_adjacent():
    print("[--sftp-group == --group restores same-folder adjacency]")
    ns = wtssh.build_parser().parse_args(["--sftp-group", "files", "list"])
    check("parser accepts --sftp-group before subcommand",
          ns.sftp_group == "files")
    old = wtssh.SFTP_GROUP
    wtssh.SFTP_GROUP = wtssh.GROUP
    try:
        write_settings([])
        out, err, code = run(wtssh.action_add,
                             add_args(name="same", host="s.example", sftp=True))
        doc = json.loads(out)
        check("add ok under shared group", code is None, out + err)
        check("add sftpGroup is the shared group name, not hardcoded sftp",
              doc.get("sftpGroup") == wtssh.GROUP, out)
        data = wtssh.load()
        ssh = wtssh.find_profile(data, "same")
        comp = wtssh.find_sftp_profile(data, "same")
        guids = folder_guids(wtssh.get_folder(data))
        check("companion adjacent to ssh in shared group",
              ssh is not None and comp is not None
              and guids.index(comp["guid"]) == guids.index(ssh["guid"]) + 1,
              str(guids))
        out, err, code = run(wtssh.action_list,
                             types.SimpleNamespace(group=None, full=False))
        payload = json.loads(out)
        row = next(r for r in payload["groups"][wtssh.GROUP]
                   if r["name"] == "same")
        check("list sftpGroup is the shared group name",
              row.get("sftp") is True
              and row.get("sftpGroup") == wtssh.GROUP, out)
        out, err, code = run(wtssh.action_move,
                             types.SimpleNamespace(name="same", top=True,
                                                   bottom=False, before=None,
                                                   after=None))
        check("move ok under shared group", code is None, out + err)
        data = wtssh.load()
        ssh = wtssh.find_profile(data, "same")
        comp = wtssh.find_sftp_profile(data, "same")
        guids = folder_guids(wtssh.get_folder(data))
        check("move keeps companion adjacent under shared group",
              ssh is not None and comp is not None
              and guids.index(comp["guid"]) == guids.index(ssh["guid"]) + 1,
              str(guids))
    finally:
        wtssh.SFTP_GROUP = old
        run(wtssh.action_remove,
            types.SimpleNamespace(name="same", force=False))


def test_migrate_legacy_companion_folder():
    print("[edit --sftp migrates a companion pinned in the ssh group]")
    write_settings([])
    run(wtssh.action_add, add_args(name="legacy", host="l.example"))
    data = wtssh.load()
    ssh = wtssh.find_profile(data, "legacy")
    # plant a canonical companion in the ssh folder (pre-change layout)
    line = wtssh.sftp_line("legacy")
    wtssh.ensure_shim()
    guid = "{eeeeeeee-0000-0000-0000-000000000009}"
    data["profiles"]["list"].append(
        {"closeOnExit": "automatic", "commandline": line,
         "guid": guid, "icon": wtssh.SFTP_ICON, "name": "sftp:legacy"})
    data["newTabMenu"][0]["entries"].append(
        {"type": "profile", "icon": None, "profile": guid})
    wtssh.SETTINGS.write_text(json.dumps(data), encoding="utf-8")
    out, err, code = run(wtssh.action_list,
                         types.SimpleNamespace(group=None, full=False))
    payload = json.loads(out)
    rows = payload["groups"]["ssh"]
    row = next(r for r in rows if r["name"] == "legacy")
    check("pre-migration list sftpGroup is ssh (actual pin)",
          row.get("sftp") is True and row.get("sftpGroup") == "ssh", out)
    check("pre-migration sftp folder not listed as an ssh group",
          "sftp" not in payload["groups"], out)
    everything = rows + payload["ungrouped"] + payload["hidden"]
    check("pre-migration no companion row leaked",
          all(not str(r["name"]).startswith("sftp") for r in everything)
          and all(r["name"] != ":legacy" for r in everything), out)
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="legacy", sftp=True))
    doc = json.loads(out)
    check("migration reports changed",
          code is None and doc.get("changed") is True
          and doc.get("sftpGroup") == "sftp", out + err)
    data = wtssh.load()
    ssh_guids = folder_guids(wtssh.get_folder(data))
    sftp_guids = folder_guids(wtssh.get_sftp_folder(data))
    check("migrated companion left the ssh group",
          guid not in ssh_guids, str(ssh_guids))
    check("migrated companion landed in sftp group",
          guid in sftp_guids, str(sftp_guids))
    check("ssh entry stayed in ssh group",
          ssh is not None and ssh["guid"] in ssh_guids)
    out, err, code = run(wtssh.action_list,
                         types.SimpleNamespace(group=None, full=False))
    payload = json.loads(out)
    row = next(r for r in payload["groups"]["ssh"] if r["name"] == "legacy")
    check("post-migration list sftpGroup is sftp",
          row.get("sftp") is True and row.get("sftpGroup") == "sftp", out)
    run(wtssh.action_remove,
        types.SimpleNamespace(name="legacy", force=False))


def test_dual_pin_and_icon_repair():
    print("[edit --sftp sweeps leftover pins; icon repair counts as changed]")
    write_settings([])
    run(wtssh.action_add, add_args(name="dual", host="d.example"))
    data = wtssh.load()
    ssh = wtssh.find_profile(data, "dual")
    line = wtssh.sftp_line("dual")
    wtssh.ensure_shim()
    guid = "{eeeeeeee-0000-0000-0000-00000000000a}"
    data["profiles"]["list"].append(
        {"closeOnExit": "never", "commandline": line,
         "guid": guid, "name": "sftp:dual"})  # icon missing
    # sftp folder FIRST so the old first-hit short-circuit would skip sweep
    sftp_folder = {"type": "folder", "name": "sftp", "icon": None,
                   "inline": "never", "allowEmpty": False,
                   "entries": [{"type": "profile", "icon": None,
                                "profile": guid}]}
    data.setdefault("newTabMenu", []).insert(0, sftp_folder)
    data["newTabMenu"][1]["entries"].append(
        {"type": "profile", "icon": None, "profile": guid})
    wtssh.SETTINGS.write_text(json.dumps(data), encoding="utf-8")
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="dual", sftp=True))
    doc = json.loads(out)
    check("dual-pin + missing icon reports changed",
          code is None and doc.get("changed") is True, out + err)
    data = wtssh.load()
    pins = wtssh.guid_folder_names(data, guid)
    check("leftover ssh pin swept; unique sftp pin remains",
          pins == ["sftp"], str(pins))
    comp = wtssh.find_sftp_profile(data, "dual")
    check("icon repaired",
          comp is not None and comp.get("icon") == wtssh.SFTP_ICON)
    out, err, code = run(wtssh.action_edit,
                         edit_args(name="dual", sftp=True))
    doc = json.loads(out)
    check("canonical unique pin is a no-op",
          code is None and doc.get("changed") is False, out + err)
    data = wtssh.load()
    check("second edit did not reshuffle the unique pin",
          wtssh.guid_folder_names(data, guid) == ["sftp"])
    check("ssh entry stayed in ssh group",
          ssh is not None
          and ssh["guid"] in folder_guids(wtssh.get_folder(data)))
    run(wtssh.action_remove,
        types.SimpleNamespace(name="dual", force=False))


def main():
    setup_env()
    test_add_sftp()
    test_edit_sftp_idempotent()
    test_rename_remove_move_propagate()
    test_cmd_unsafe_refused()
    test_resolve_tunnel_mode()
    test_doctor_findings()
    test_filezilla_auto_modes()
    test_orphan_companion_removal()
    test_rename_collision_no_halfstate()
    test_spaced_shim_path()
    test_sftp_group_override_adjacent()
    test_migrate_legacy_companion_folder()
    test_dual_pin_and_icon_repair()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {FAILURES}")
        sys.exit(1)
    print("all m5 sftp-menu checks passed")


if __name__ == "__main__":
    main()
