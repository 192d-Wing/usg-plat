# SPDX-License-Identifier: MIT
"""Unit tests for deploy/verify/dnf/usg_plat_verify.py.

Run: python3 -m unittest deploy/tests/verify/test_dnf_plugin.py
(or `python3 -I deploy/tests/verify/test_dnf_plugin.py`).

A fake `dnf` module stands in for dnf4 so the tests run on any host; the
transaction items use the real dnf.transaction constant names. verify-pkg is
a stub script that records its argv and environment.

COMPLIANCE MAPPING:
- NIST 800-53: SI-7(15), CM-14, SR-11 (test evidence for the dnf gate)
"""

import ast
import importlib.util
import os
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, "..", "..", "verify", "dnf", "usg_plat_verify.py")

# The PKG_* names exported by dnf/transaction.py in dnf 4.14 (Rocky 9),
# exactly; the plugin may use no other.  Values are deliberately unlike
# libdnf's so that a hard-coded integer in the plugin would fail the tests.
ACTION_NAMES = (
    "PKG_DOWNGRADE",
    "PKG_DOWNGRADED",
    "PKG_INSTALL",
    "PKG_OBSOLETE",
    "PKG_OBSOLETED",
    "PKG_REINSTALL",
    "PKG_REINSTALLED",
    "PKG_REMOVE",
    "PKG_UPGRADE",
    "PKG_UPGRADED",
    "PKG_CLEANUP",
    "PKG_ERASE",
    "PKG_SCRIPTLET",
    "PKG_VERIFY",
)


def _fake_dnf():
    dnf = types.ModuleType("dnf")
    transaction = types.ModuleType("dnf.transaction")
    for i, n in enumerate(ACTION_NAMES):
        setattr(transaction, n, 1000 + i)
    exceptions = types.ModuleType("dnf.exceptions")

    class Error(Exception):
        pass

    exceptions.Error = Error

    class Plugin(object):
        def __init__(self, base, cli):
            pass

    dnf.Plugin = Plugin
    dnf.transaction = transaction
    dnf.exceptions = exceptions
    return {"dnf": dnf, "dnf.transaction": transaction, "dnf.exceptions": exceptions}


FAKE = _fake_dnf()
with mock.patch.dict(sys.modules, FAKE):
    _spec = importlib.util.spec_from_file_location("usg_plat_verify", PLUGIN)
    upv = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(upv)
T = FAKE["dnf.transaction"]
DnfError = FAKE["dnf.exceptions"].Error


class Pkg(object):
    def __init__(self, name, version, release, arch, local, repo="usg-plat", epoch=0):
        self.name, self.version, self.release, self.arch = name, version, release, arch
        self.epoch, self.reponame, self._local = epoch, repo, local
        self.evr = "%s-%s" % (version, release)
        self.opened = False

    def localPkg(self):
        self.opened = True
        return self._local


class Item(object):
    def __init__(self, action, pkg):
        self.action, self.pkg = action, pkg


STUB = """#!/bin/sh
printf '%s\\n' "$@" > "{d}/argv"
printf '%s\\n' "${{USG_PLAT_VERIFY_SUMS_DIR-unset}}" > "{d}/sumsdir"
exit $(cat "{d}/rc")
"""


class PluginTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.stub = os.path.join(self.d, "verify-pkg")
        with open(self.stub, "w") as f:
            f.write(STUB.format(d=self.d))
        os.chmod(self.stub, 0o755)
        self.set_rc(0)
        self.conf = os.path.join(self.d, "verify.conf")
        with open(self.conf, "w") as f:
            f.write('NAMES="platd usg-plat-verify"\nALLOW_DOWNGRADE=0\n')
        self.rpm = os.path.join(self.d, "platd-0.3.0-1.x86_64.rpm")
        with open(self.rpm, "wb") as f:
            f.write(b"not really an rpm")
        patches = [
            mock.patch.object(upv, "VERIFY_PKG", self.stub),
            mock.patch.object(upv, "CONF_PATH", self.conf),
            mock.patch.object(upv, "LAST_REFUSAL", os.path.join(self.d, "last-refusal")),
            mock.patch.object(upv, "FETCH_SUMS", os.path.join(self.d, "no-fetch-sums")),
            mock.patch.object(upv, "_log", lambda *a: None),
            mock.patch.object(upv, "read_header", self.fake_header),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        os.environ.pop("USG_PLAT_ALLOW_DOWNGRADE", None)
        os.environ.pop("USG_PLAT_VERIFY_SUMS_DIR", None)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.header = ("platd", "0", "0.3.0", "1", "x86_64")

    def tearDown(self):
        self.tmp.cleanup()

    def fake_header(self, fd):
        os.fstat(fd)  # must be an open descriptor
        return self.header

    def set_rc(self, rc):
        with open(os.path.join(self.d, "rc"), "w") as f:
            f.write("%d\n" % rc)

    def run_plugin(self, *items):
        base = types.SimpleNamespace(transaction=list(items))
        plugin = upv.UsgPlatVerify(base, None)
        plugin.pre_transaction()

    def argv(self):
        path = os.path.join(self.d, "argv")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return f.read().split("\n")[:-1]

    def sumsdir(self):
        with open(os.path.join(self.d, "sumsdir")) as f:
            return f.read().strip()

    def pkg(self, **kw):
        args = dict(name="platd", version="0.3.0", release="1", arch="x86_64", local=self.rpm)
        args.update(kw)
        return Pkg(**args)

    # --- accept path -----------------------------------------------------

    def test_accept_passes_exact_interface(self):
        self.run_plugin(Item(T.PKG_INSTALL, self.pkg()))
        import hashlib

        with open(self.rpm, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(
            self.argv(),
            ["--name", "platd", "--version", "0.3.0-1", "--arch", "x86_64", "--sha256", digest],
        )
        self.assertEqual(self.sumsdir(), "unset")

    def test_inherited_sums_dir_is_dropped_for_repo_packages(self):
        os.environ["USG_PLAT_VERIFY_SUMS_DIR"] = "/attacker"
        self.run_plugin(Item(T.PKG_UPGRADE, self.pkg()))
        self.assertEqual(self.sumsdir(), "unset")

    def test_commandline_relative_path_made_absolute(self):
        cwd = os.getcwd()
        os.chdir(self.d)
        try:
            pkg = self.pkg(local=os.path.basename(self.rpm), repo="@commandline")
            with mock.patch.object(upv, "open_and_measure", wraps=upv.open_and_measure) as m:
                self.run_plugin(Item(T.PKG_INSTALL, pkg))
            opened = m.call_args[0][0]
        finally:
            os.chdir(cwd)
        self.assertTrue(os.path.isabs(opened))
        self.assertEqual(os.path.realpath(opened), os.path.realpath(self.rpm))
        self.assertEqual(os.path.realpath(self.sumsdir()), os.path.realpath(self.d))

    # --- refusals ----------------------------------------------------------

    def test_verify_pkg_refusal_raises_dnf_error(self):
        self.set_rc(1)
        with self.assertRaises(DnfError) as cm:
            self.run_plugin(Item(T.PKG_INSTALL, self.pkg()))
        self.assertIn("usg-plat-verify: refusing platd-0.3.0-1", str(cm.exception))
        # verify-pkg writes its own record; the plugin does not overwrite it.
        self.assertFalse(os.path.exists(os.path.join(self.d, "last-refusal")))

    def test_verify_pkg_usage_error_refuses(self):
        self.set_rc(2)
        with self.assertRaises(DnfError):
            self.run_plugin(Item(T.PKG_INSTALL, self.pkg()))

    def test_verify_pkg_missing_refuses(self):
        with mock.patch.object(upv, "VERIFY_PKG", os.path.join(self.d, "absent")):
            with self.assertRaises(DnfError) as cm:
                self.run_plugin(Item(T.PKG_INSTALL, self.pkg()))
        self.assertIn("not found", str(cm.exception))

    def test_verify_pkg_timeout_refuses(self):
        with open(self.stub, "w") as f:
            f.write("#!/bin/sh\nsleep 5\n")
        with mock.patch.object(upv, "VERIFY_TIMEOUT", 0.2):
            with self.assertRaises(DnfError) as cm:
                self.run_plugin(Item(T.PKG_INSTALL, self.pkg()))
        self.assertIn("timed out", str(cm.exception))

    def test_downgrade_refused_then_allowed_by_override(self):
        with self.assertRaises(DnfError) as cm:
            self.run_plugin(Item(T.PKG_DOWNGRADE, self.pkg()))
        self.assertIn("downgrade", str(cm.exception))
        self.assertIsNone(self.argv())
        with open(os.path.join(self.d, "last-refusal")) as f:
            self.assertIn("platd 0.3.0-1 downgrade", f.read())
        os.environ["USG_PLAT_ALLOW_DOWNGRADE"] = "1"
        self.run_plugin(Item(T.PKG_DOWNGRADE, self.pkg()))
        self.assertIsNotNone(self.argv())

    def test_downgrade_allowed_by_conf(self):
        with open(self.conf, "a") as f:
            f.write("ALLOW_DOWNGRADE=1\n")
        self.run_plugin(Item(T.PKG_DOWNGRADE, self.pkg()))
        self.assertIsNotNone(self.argv())

    def test_header_mismatch_refused(self):
        for header in (
            ("platd", "0", "0.3.1", "1", "x86_64"),
            ("openssl", "0", "0.3.0", "1", "x86_64"),
            ("platd", "0", "0.3.0", "1", "aarch64"),
            ("platd", "1", "0.3.0", "1", "x86_64"),
        ):
            self.header = header
            with self.assertRaises(DnfError) as cm:
                self.run_plugin(Item(T.PKG_UPGRADE, self.pkg()))
            self.assertIn("does not match", str(cm.exception))
        self.assertIsNone(self.argv())

    def test_symlink_refused_with_o_nofollow(self):
        link = os.path.join(self.d, "link.rpm")
        os.symlink(self.rpm, link)
        real_open = os.open
        flags_seen = []

        def spy(path, flags, *a):
            flags_seen.append(flags)
            return real_open(path, flags, *a)

        with mock.patch.object(upv.os, "open", spy):
            with self.assertRaises(DnfError) as cm:
                self.run_plugin(Item(T.PKG_INSTALL, self.pkg(local=link)))
        self.assertTrue(flags_seen and flags_seen[0] & os.O_NOFOLLOW)
        self.assertIn("cannot open", str(cm.exception))
        self.assertIsNone(self.argv())

    def test_non_regular_file_refused(self):
        with self.assertRaises(DnfError):
            self.run_plugin(Item(T.PKG_INSTALL, self.pkg(local=self.d)))

    def test_unknown_action_for_our_name_refused(self):
        with self.assertRaises(DnfError):
            self.run_plugin(Item(424242, self.pkg()))

    def test_shadowed_name_from_other_repo_is_checked(self):
        self.set_rc(1)
        with self.assertRaises(DnfError):
            self.run_plugin(Item(T.PKG_INSTALL, self.pkg(repo="epel")))

    def test_missing_conf_keeps_default_names(self):
        os.unlink(self.conf)
        self.set_rc(1)
        with self.assertRaises(DnfError):
            self.run_plugin(Item(T.PKG_INSTALL, self.pkg()))

    # --- pass-through --------------------------------------------------------

    def test_other_names_never_opened_or_hashed(self):
        pkg = self.pkg(name="openssl", local="/nonexistent")
        with mock.patch.object(upv, "open_and_measure") as m:
            self.run_plugin(Item(T.PKG_INSTALL, pkg), Item(T.PKG_UPGRADE, pkg))
        m.assert_not_called()
        self.assertFalse(pkg.opened)
        self.assertIsNone(self.argv())

    def test_outgoing_items_pass(self):
        self.set_rc(1)
        for action in (T.PKG_REMOVE, T.PKG_UPGRADED, T.PKG_DOWNGRADED, T.PKG_OBSOLETED):
            self.run_plugin(Item(action, self.pkg(local="/nonexistent")))
        self.assertIsNone(self.argv())

    def test_resolved_calls_fetch_sums_with_tags(self):
        fetch = os.path.join(self.d, "fetch-sums")
        with open(fetch, "w") as f:
            f.write('#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/fetch"\nexit 3\n' % self.d)
        os.chmod(fetch, 0o755)
        base = types.SimpleNamespace(
            transaction=[
                Item(T.PKG_UPGRADE, self.pkg()),
                Item(T.PKG_INSTALL, self.pkg(name="usg-plat-verify", arch="noarch")),
                Item(T.PKG_INSTALL, self.pkg(name="openssl", version="9.9.9")),
                Item(T.PKG_INSTALL, self.pkg(version="0.4.0", repo="@commandline")),
            ]
        )
        with mock.patch.object(upv, "FETCH_SUMS", fetch):
            upv.UsgPlatVerify(base, None).resolved()  # non-zero exit is ignored
        with open(os.path.join(self.d, "fetch")) as f:
            self.assertEqual(f.read().split(), ["v0.3.0"])


class SourceTest(unittest.TestCase):
    """Static checks on the plugin source."""

    @classmethod
    def setUpClass(cls):
        with open(PLUGIN) as f:
            cls.tree = ast.parse(f.read(), PLUGIN)

    def test_no_shell_true(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                self.assertIsInstance(node.value, ast.Constant)
                self.assertIs(node.value.value, False)
        src = ast.dump(self.tree)
        self.assertNotIn("os.system", src)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("system", "popen", "check_output", "getoutput"))

    def test_actions_only_by_named_constant(self):
        """No integer literal is compared with `.action` or put in the action sets."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Compare):
                operands = [node.left] + list(node.comparators)
                touches_action = any(
                    isinstance(o, ast.Attribute) and o.attr == "action" for o in operands
                )
                if touches_action:
                    for o in operands:
                        for sub in ast.walk(o):
                            self.assertFalse(
                                isinstance(sub, ast.Constant) and isinstance(sub.value, int),
                                "integer compared with action at line %d" % node.lineno,
                            )
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in ("INCOMING", "PASSTHROUGH")
                for t in node.targets
            ):
                consts = [
                    e
                    for e in ast.walk(node.value)
                    if isinstance(e, ast.Attribute) and e.attr.startswith("PKG_")
                ]
                self.assertTrue(consts)
                for e in consts:
                    self.assertEqual(ast.unparse(e.value), "dnf.transaction")
                for e in ast.walk(node.value):
                    self.assertFalse(isinstance(e, ast.Constant) and isinstance(e.value, int))

    def test_no_identity_regexp(self):
        with open(PLUGIN) as f:
            self.assertNotIn("identity-regexp", f.read())


if __name__ == "__main__":
    unittest.main()
