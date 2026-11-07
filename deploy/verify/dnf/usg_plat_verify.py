# SPDX-License-Identifier: MIT
"""dnf4 plugin: refuse usg-plat packages that verify-pkg does not accept.

Installed as %{python3_sitelib}/dnf-plugins/usg_plat_verify.py and enabled
by /etc/dnf/plugins/usg_plat_verify.conf.

pre_transaction() runs after download and the rpm transaction test and
before rpm unpacks anything. For every incoming package whose name is one
of ours it opens the file once (O_NOFOLLOW), hashes that descriptor, reads
the rpm header from the same descriptor, and hands name, version, arch and
digest to verify-pkg, which checks the keyless cosign signature over the
release SHA256SUMS. Any refusal raises dnf.exceptions.Error, which aborts
the whole transaction (accepted residual, POAM-044 (g)).

rpm reopens the package by path after this check, so the file and every
ancestor directory must be owned by uid 0 and not group- or other-writable
(root_only); dnf's cache meets that. A local install (`dnf install ./x.rpm`)
must be staged in a root-only directory such as /root/pkgs, never /tmp or a
home directory. verify.conf is read only under the same rule.

verify-pkg gets the caller's environment without USG_PLAT_VERIFY_* and
TMPDIR (its test hooks); USG_PLAT_ALLOW_DOWNGRADE=1 is an operator override
and is logged when it allows a downgrade.

COMPLIANCE MAPPING:
- NIST 800-53: SI-7(15) (Code Authentication) - signature checked before install
- NIST 800-53: CM-14 (Signed Components) - unsigned or mis-signed packages refused
- NIST 800-53: SR-11 (Component Authenticity) - exact signer identity per release tag

POAM: rpm -i/-U and dnf5 bypass this plugin; root can disable it (POAM-044 (c)).
"""

import datetime
import hashlib
import os
import re
import stat
import subprocess
import syslog

import dnf
import dnf.exceptions
import dnf.transaction

VERIFY_PKG = "/usr/libexec/usg-plat-verify/verify-pkg"
FETCH_SUMS = "/usr/libexec/usg-plat-verify/fetch-sums"
CONF_PATH = "/etc/usg-plat-verify/verify.conf"
STATE_DIR = "/var/lib/usg-plat-verify"
TEXTFILE_DIR = "/var/lib/node_exporter/textfile_collector"
DEFAULT_NAMES = ("platd", "usg-plat-verify")
VERIFY_TIMEOUT = 90
FETCH_TIMEOUT = 60
COMMANDLINE_REPO = "@commandline"
# Owners trusted by root_only(); the tests add their own uid and a top.
TRUSTED_UIDS = (0,)
TRUST_TOP = None

# Incoming packages: these are the files rpm would unpack.
INCOMING = frozenset(
    (
        dnf.transaction.PKG_INSTALL,
        dnf.transaction.PKG_UPGRADE,
        dnf.transaction.PKG_REINSTALL,
        dnf.transaction.PKG_DOWNGRADE,
        dnf.transaction.PKG_OBSOLETE,
    )
)
# Outgoing items: nothing is unpacked, so they pass. Any other action on
# one of our names (dnf 4.14 has no named reason-change constant) refuses.
# Only constants present in dnf 4.14 are used: a missing attribute would make
# dnf skip the plugin at load time, which fails open.
PASSTHROUGH = frozenset(
    (
        dnf.transaction.PKG_REMOVE,
        dnf.transaction.PKG_UPGRADED,
        dnf.transaction.PKG_DOWNGRADED,
        dnf.transaction.PKG_OBSOLETED,
        dnf.transaction.PKG_REINSTALLED,
    )
)


class Refusal(Exception):
    """A reason to refuse one package.

    recorded is True when verify-pkg already logged the decision and wrote
    last-refusal, so the plugin does not overwrite its record.
    """

    def __init__(self, reason, recorded=False):
        super(Refusal, self).__init__(reason)
        self.recorded = recorded


class ConfError(Exception):
    """verify.conf is unsafe or not a literal assignment file."""


def root_only(path):
    """True when path and every ancestor directory are owned by a trusted uid
    (root), are not symlinks and are neither group- nor other-writable.

    A sticky world-writable directory such as /tmp fails. Same rule as the
    shell root_only() in verify-pkg and apt-hook.
    """
    # COMPLIANCE MAPPING:
    # - NIST 800-53: SI-7(15) (Code Authentication) - the file rpm reopens
    #   after this check can be written only by root
    if not os.path.isabs(path) or path != os.path.normpath(path):
        return False
    p = path
    while True:
        if TRUST_TOP is not None and p == TRUST_TOP:
            return True
        try:
            st = os.lstat(p)
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode) or st.st_uid not in TRUSTED_UIDS:
            return False
        if st.st_mode & 0o022:
            return False
        if p == "/":
            return True
        p = os.path.dirname(p)


# Literal assignments only, the subset on which `sh -c '. conf'` and this
# parser agree (unit-tested): NAME=word, NAME="text" or NAME='text' with no
# expansion, escape, tilde or command characters, optionally after `export `.
_ASSIGN = re.compile(
    r"""(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"$`\\]*)"|'([^']*)'|([^\s"'$`\\;&|<>(){}#~]*))[ \t]*"""
)


def load_conf(path=None):
    """Read the shell-style key=value verify.conf.

    A missing file keeps the defaults, which still gate our names (fail
    closed). A file that is not root_only() or has a line that is not a
    literal assignment raises ConfError: the plugin then refuses our names,
    as verify-pkg would.
    """
    path = path or CONF_PATH
    conf = {"NAMES": " ".join(DEFAULT_NAMES), "ALLOW_DOWNGRADE": "0"}
    if not os.path.lexists(path):
        return conf
    if not root_only(path):
        raise ConfError(
            "%s (or a parent directory) is not root-owned or is group/other-writable"
            % path
        )
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise ConfError("cannot read %s: %s" % (path, e))
    for n, line in enumerate(lines, 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        m = _ASSIGN.fullmatch(text)
        if not m:
            raise ConfError("%s line %d is not a literal assignment" % (path, n))
        value = next(v for v in m.groups()[1:] if v is not None)
        conf[m.group(1)] = value
    return conf


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def _epoch(value):
    text = _text(value)
    return text if text not in ("", "None") else "0"


def open_and_measure(path):
    """Open path once without following symlinks; hash it and read its header.

    Returns (sha256 hex, (name, epoch, version, release, arch)).
    """
    # The digest and the header come from the same descriptor, but rpm
    # reopens the path later: root_only() in _check is what stops a swap
    # between this check and rpm's unpack.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise Refusal("cannot open %s: %s" % (path, e.strerror or e))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refusal("%s is not a regular file" % path)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        header = read_header(fd)
        return digest.hexdigest(), header
    finally:
        os.close(fd)


def read_header(fd):
    """Read (name, epoch, version, release, arch) from an rpm descriptor."""
    import rpm

    ts = rpm.TransactionSet()
    # Signatures are not the trust anchor here (gpgcheck=0 by design); the
    # cosign-verified SHA256SUMS is. Digest checks stay on.
    nosig = getattr(rpm, "_RPMVSF_NOSIGNATURES", 0)
    ts.setVSFlags(nosig)
    try:
        hdr = ts.hdrFromFdno(fd)
    except rpm.error as e:
        raise Refusal("unreadable rpm header: %s" % e)
    return (
        _text(hdr[rpm.RPMTAG_NAME]),
        _epoch(hdr[rpm.RPMTAG_EPOCH]),
        _text(hdr[rpm.RPMTAG_VERSION]),
        _text(hdr[rpm.RPMTAG_RELEASE]),
        _text(hdr[rpm.RPMTAG_ARCH]),
    )


def _nevra(pkg):
    return "%s-%s" % (pkg.name, pkg.evr)


def _log(priority, message):
    try:
        syslog.openlog("usg-plat-verify", 0, syslog.LOG_AUTHPRIV)
        syslog.syslog(priority, message)
    except OSError:
        pass


def _clean(value):
    """Printable, bounded form, as clean() in verify-pkg."""
    return re.sub(r"[^A-Za-z0-9._+:~-]", "?", _text(value))[:64]


def _atomic_write(path, text, mode=None):
    tmp = "%s.%d" % (path, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


PROM = (
    "# HELP usg_plat_verify_refusals_total usg-plat packages refused by the install gate.\n"
    "# TYPE usg_plat_verify_refusals_total counter\n"
    "usg_plat_verify_refusals_total %d\n"
    "# HELP usg_plat_verify_last_refusal_timestamp_seconds Time of the last refusal.\n"
    "# TYPE usg_plat_verify_last_refusal_timestamp_seconds gauge\n"
    "usg_plat_verify_last_refusal_timestamp_seconds %d\n"
)


def _record_refusal(pkg, reason):
    """Same records as record_refusal() in verify-pkg (best effort): atomic
    last-refusal, refusals_total counter and the optional node-exporter
    textfile, so alerting sees plugin refusals too."""
    now = datetime.datetime.now(datetime.timezone.utc)
    n = 1
    if os.path.isdir(STATE_DIR):
        _atomic_write(
            os.path.join(STATE_DIR, "last-refusal"),
            "%s %s %s %s\n"
            % (now.strftime("%Y-%m-%dT%H:%M:%SZ"), _clean(pkg.name), _clean(pkg.evr), reason),
        )
        total = os.path.join(STATE_DIR, "refusals_total")
        try:
            with open(total, encoding="utf-8") as f:
                old = f.read().strip()
        except OSError:
            old = ""
        n = (int(old) if old.isdigit() else 0) + 1
        _atomic_write(total, "%d\n" % n)
    if os.path.isdir(TEXTFILE_DIR):
        _atomic_write(
            os.path.join(TEXTFILE_DIR, "usg-plat-verify.prom"),
            PROM % (n, int(now.timestamp())),
            0o644,
        )


def _tag(version):
    return "v" + version.split("-", 1)[0]


class UsgPlatVerify(dnf.Plugin):
    name = "usg_plat_verify"

    def __init__(self, base, cli):
        super(UsgPlatVerify, self).__init__(base, cli)
        self.base = base

    def _settings(self):
        """(names, allow_downgrade, conf_error or None)."""
        try:
            conf = load_conf()
        except ConfError as e:
            return frozenset(DEFAULT_NAMES), False, str(e)
        names = frozenset(conf.get("NAMES", "").split()) or frozenset(DEFAULT_NAMES)
        allow_downgrade = (
            conf.get("ALLOW_DOWNGRADE") == "1"
            or os.environ.get("USG_PLAT_ALLOW_DOWNGRADE") == "1"
        )
        return names, allow_downgrade, None

    def resolved(self):
        """Best effort: fetch SHA256SUMS for the repo versions being installed."""
        names, _, _ = self._settings()
        tags = set()
        for item in self.base.transaction or ():
            pkg = item.pkg
            if (
                item.action in INCOMING
                and pkg.name in names
                and pkg.reponame != COMMANDLINE_REPO
            ):
                tags.add(_tag(pkg.version))
        if not tags or not os.access(FETCH_SUMS, os.X_OK):
            return
        try:
            subprocess.run(
                [FETCH_SUMS] + sorted(tags),
                shell=False,
                stdin=subprocess.DEVNULL,
                timeout=FETCH_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    def pre_transaction(self):
        names, allow_downgrade, conf_error = self._settings()
        for item in self.base.transaction:
            pkg = item.pkg
            # Name filter first: distro packages get no per-file work.
            if pkg.name not in names:
                continue
            if item.action in PASSTHROUGH:
                continue
            try:
                if item.action not in INCOMING:
                    raise Refusal("unknown transaction action %r" % (item.action,))
                if conf_error:
                    raise Refusal(conf_error)
                self._check(item, allow_downgrade)
            except Refusal as e:
                reason = str(e)
                _log(syslog.LOG_ERR, "refusing %s: %s" % (_nevra(pkg), reason))
                if not e.recorded:
                    _record_refusal(pkg, reason)
                raise dnf.exceptions.Error(
                    "usg-plat-verify: refusing %s: %s" % (_nevra(pkg), reason)
                )

    def _check(self, item, allow_downgrade):
        pkg = item.pkg
        # COMPLIANCE MAPPING:
        # - NIST 800-53: SI-7(15), CM-14 - no rollback to an older signed release
        if item.action == dnf.transaction.PKG_DOWNGRADE and not allow_downgrade:
            raise Refusal(
                "downgrade refused (set ALLOW_DOWNGRADE=1 or USG_PLAT_ALLOW_DOWNGRADE=1)"
            )
        if item.action == dnf.transaction.PKG_DOWNGRADE:
            _log(
                syslog.LOG_WARNING,
                "downgrade of %s allowed by ALLOW_DOWNGRADE%s"
                % (
                    _nevra(pkg),
                    " (USG_PLAT_ALLOW_DOWNGRADE=1 in the environment)"
                    if os.environ.get("USG_PLAT_ALLOW_DOWNGRADE") == "1"
                    else "",
                ),
            )
        local = pkg.localPkg()
        if not local:
            raise Refusal("no local package file")
        # @commandline paths are relative to the cwd dnf was started in.
        path = os.path.abspath(local)
        if not root_only(path):
            raise Refusal(
                "%s: the file or a parent directory is not root-owned or is "
                "group/other-writable (stage local packages in a root-only directory)"
                % path
            )
        digest, header = open_and_measure(path)
        expected = (pkg.name, _epoch(pkg.epoch), pkg.version, pkg.release, pkg.arch)
        if header != expected:
            raise Refusal(
                "rpm header %s does not match transaction %s"
                % ("-".join(header), "-".join(expected))
            )
        # verify-pkg's test hooks never cross from dnf's environment.
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("USG_PLAT_VERIFY_") and k != "TMPDIR"
        }
        if pkg.reponame == COMMANDLINE_REPO:
            env["USG_PLAT_VERIFY_SUMS_DIR"] = os.path.dirname(path)
        argv = [
            VERIFY_PKG,
            "--name",
            pkg.name,
            "--version",
            "%s-%s" % (pkg.version, pkg.release),
            "--arch",
            pkg.arch,
            "--sha256",
            digest,
        ]
        try:
            result = subprocess.run(
                argv,
                shell=False,
                env=env,
                stdin=subprocess.DEVNULL,
                timeout=VERIFY_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            raise Refusal("verify-pkg not found at %s" % VERIFY_PKG)
        except subprocess.TimeoutExpired:
            raise Refusal("verify-pkg timed out after %d s" % VERIFY_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as e:
            raise Refusal("verify-pkg failed to run: %s" % e)
        if result.returncode == 1:
            raise Refusal("signature verification refused (verify-pkg exit 1)", True)
        if result.returncode != 0:
            raise Refusal(
                "verify-pkg exit %d (config or usage error)" % result.returncode
            )
