"""Global options must survive every subcommand (offline, no vault/agent):

Regression: the global `--keys DIR` (vault keys dir) and the positional
`keys` of `agent load` / `agent unload` shared one argparse dest. argparse
copies a subparser's namespace over the parent's, so the key-name list
overwrote the dir: `agent load k1` crashed in main() with
`Path(['k1'])` (TypeError), and `--keys X agent load` silently dropped X
-- the drill sandbox fell back to the REAL vault keys dir.

The action functions are replaced by recorders, so nothing here unwraps a
key, talks to ssh-agent, or touches the live config.

Run:  python tests/test_global_options.py   (or via pytest)
"""
import argparse
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wtssh  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="wtssh-test-globals-"))


def setup_env():
    wtssh.KEYS_DIR = TMP / "default-keys"
    wtssh.SECRETS_DIR = TMP / "secrets"
    wtssh.AGENT_DIR = TMP / "agent"
    wtssh.SETTINGS = TMP / "settings.json"


def _drive(argv, action_attr):
    """Run main(argv) with `action_attr` swapped for a recorder; return
    (args seen by the action, wtssh.KEYS_DIR at call time)."""
    seen = {}

    def recorder(args):
        seen["args"] = args
        seen["keys_dir"] = wtssh.KEYS_DIR

    saved_fn = getattr(wtssh, action_attr)
    saved_dir = wtssh.KEYS_DIR
    setattr(wtssh, action_attr, recorder)
    try:
        wtssh.main(argv)
    finally:
        setattr(wtssh, action_attr, saved_fn)
        wtssh.KEYS_DIR = saved_dir
    assert "args" in seen, f"{argv}: action never ran"
    return seen["args"], seen["keys_dir"]


def test_agent_load_with_names_no_global():
    args, kdir = _drive(["agent", "load", "k1"], "action_agent_load")
    assert args.keys == ["k1"], args
    assert kdir == TMP / "default-keys", kdir


def test_agent_load_no_names_keeps_global_dir():
    sandbox = TMP / "sandbox-keys"
    args, kdir = _drive(["--keys", str(sandbox), "agent", "load"],
                        "action_agent_load")
    assert args.keys == [], args
    assert kdir == sandbox.resolve(), kdir


def test_agent_load_names_and_global_dir():
    sandbox = TMP / "sandbox-keys"
    args, kdir = _drive(["--keys", str(sandbox), "agent", "load",
                         "k1", "k2", "--ttl", "8h"], "action_agent_load")
    assert args.keys == ["k1", "k2"] and args.ttl == "8h", args
    assert kdir == sandbox.resolve(), kdir


def test_agent_unload_names_and_global_dir():
    sandbox = TMP / "sandbox-keys"
    args, kdir = _drive(["--keys", str(sandbox), "agent", "unload", "k1"],
                        "action_agent_unload")
    assert args.keys == ["k1"] and args.all is False, args
    assert kdir == sandbox.resolve(), kdir


def test_global_keys_still_works_elsewhere():
    sandbox = TMP / "sandbox-keys"
    _args, kdir = _drive(["--keys", str(sandbox), "list"], "action_list")
    assert kdir == sandbox.resolve(), kdir


def _walk(parser, path=()):
    for act in parser._actions:  # test-only introspection
        if isinstance(act, argparse._SubParsersAction):
            for name, sub in act.choices.items():
                yield path + (name,), sub
                yield from _walk(sub, path + (name,))


def test_no_subcommand_dest_shadows_a_global():
    """Structural guard for the whole CLI, not just `agent`: any subparser
    argument whose dest equals a top-level option's dest silently
    overwrites it (argparse copies the sub-namespace onto the parent)."""
    ap = wtssh.build_parser()
    globals_ = {a.dest for a in ap._actions
                if a.option_strings and a.dest != "help"}
    clashes = []
    for path, sub in _walk(ap):
        for a in sub._actions:
            if a.dest in globals_:
                clashes.append((" ".join(path), a.dest))
    assert not clashes, f"subcommand dests shadow globals: {clashes}"


def main():
    setup_env()
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = []
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except Exception as e:  # noqa: BLE001 -- report every case
            print(f"  FAIL {t.__name__}  {type(e).__name__}: {e}")
            failed.append(t.__name__)
    if failed:
        print(f"\n{len(failed)} FAILURE(S): {failed}")
        sys.exit(1)
    print("\nall global-option tests passed")


if __name__ == "__main__":
    main()
