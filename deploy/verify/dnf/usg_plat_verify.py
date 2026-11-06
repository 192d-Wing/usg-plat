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

COMPLIANCE MAPPING:
- NIST 800-53: SI-7(15) (Code Authentication) - signature checked before install
- NIST 800-53: CM-14 (Signed Components) - unsigned or mis-signed packages refused
- NIST 800-53: SR-11 (Component Authenticity) - exact signer identity per release tag

POAM: rpm -i/-U and dnf5 bypass this plugin; root can disable it (POAM-044 (c)).
"""

import datetime
import hashlib
import os
import stat
import subprocess
import syslog

import dnf
import dnf.exceptions
import dnf.transaction

VERIFY_PKG = "/usr/libexec/usg-plat-verify/verify-pkg"
FETCH_SUMS = "/usr/libexec/usg-plat-verify/fetch-sums"
CONF_PATH = "/etc/usg-plat-verify/verify.conf"
LAST_REFUSAL = "/var/lib/usg-plat-verify/last-refusal"
DEFAULT_NAMES = ("platd", "usg-plat-verify")
VERIFY_TIMEOUT = 90
FETCH_TIMEOUT = 60
COMMANDLINE_REPO = "@commandline"

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


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def load_conf(path=None):
    """Read the shell-style key=value verify.conf.

    Only literal assignments are understood. A missing or unreadable file
    keeps the defaults, which still gate our names (fail closed).
    """
    conf = {"NAMES": " ".join(DEFAULT_NAMES), "ALLOW_DOWNGRADE": "0"}
    try:
        with open(path or CONF_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key.startswith("export "):
                    key = key[len("export ") :].strip()
                conf[key] = _unquote(value)
    except OSError:
        pass
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
    # COMPLIANCE MAPPING:
    # - NIST 800-53: SI-7(15) - the digest and the header come from the same
    #   descriptor, so the file cannot be swapped between check and use here
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


def _record_refusal(pkg, reason):
    """Best effort, same file verify-pkg writes, so alerting sees plugin refusals."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(LAST_REFUSAL, "w", encoding="utf-8") as f:
            f.write("%s %s %s %s\n" % (now, pkg.name, pkg.evr, reason))
    except OSError:
        pass


def _tag(version):
    return "v" + version.split("-", 1)[0]


class UsgPlatVerify(dnf.Plugin):
    name = "usg_plat_verify"

    def __init__(self, base, cli):
        super(UsgPlatVerify, self).__init__(base, cli)
        self.base = base

    def _settings(self):
        conf = load_conf()
        names = frozenset(conf.get("NAMES", "").split()) or frozenset(DEFAULT_NAMES)
        allow_downgrade = (
            conf.get("ALLOW_DOWNGRADE") == "1"
            or os.environ.get("USG_PLAT_ALLOW_DOWNGRADE") == "1"
        )
        return names, allow_downgrade

    def resolved(self):
        """Best effort: fetch SHA256SUMS for the repo versions being installed."""
        names, _ = self._settings()
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
        names, allow_downgrade = self._settings()
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
        local = pkg.localPkg()
        if not local:
            raise Refusal("no local package file")
        # @commandline paths are relative to the cwd dnf was started in.
        path = os.path.abspath(local)
        digest, header = open_and_measure(path)
        expected = (pkg.name, _epoch(pkg.epoch), pkg.version, pkg.release, pkg.arch)
        if header != expected:
            raise Refusal(
                "rpm header %s does not match transaction %s"
                % ("-".join(header), "-".join(expected))
            )
        env = dict(os.environ)
        env.pop("USG_PLAT_VERIFY_SUMS_DIR", None)
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
