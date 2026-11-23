"""`edr-agent discover`: find the nginx binary, php-fpm and php binaries, web users, web roots and the VPC range.

Nothing here is a guess: a value that cannot be found is left out, and the policies keep what local.conf
already says. Read-only on the host: /proc, the nginx and php-fpm configuration as text (includes followed
within the parser limits of client PLAN section 4.5.1), `nginx -V`, and `ip route`.
"""
import glob
import ipaddress
import os
import re
import shutil
import subprocess

from . import config as cfgmod

INCLUDE_DEPTH = 8
INCLUDE_FILES = 500
INCLUDE_BYTES = 4 * 1024 * 1024
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _run(runner, argv, timeout=5):
    try:
        p = runner(argv, capture_output=True, text=True, timeout=timeout, check=False,
                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return p.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _read_limited(path, budget):
    """Text of a regular file (no symlink out of the tree is checked by the caller), at most the remaining budget."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not os.path.isfile(path) or st.st_size > budget[0] or st.st_nlink > 100:
            return None
        data = os.read(fd, budget[0] + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    budget[0] -= len(data)
    return data.decode("utf-8", "replace")


def _statements(text):
    text = re.sub(r"#[^\n]*", "", text)
    for chunk in re.split(r"[;{}]", text):
        parts = chunk.split()
        if parts:
            yield parts


class NginxConf:
    """The directives discover needs from /etc/nginx/nginx.conf and what it includes."""

    def __init__(self, conf_path, allowed_roots=("/etc/nginx",)):
        self.users, self.roots = [], []
        self.files = 0
        self.budget = [INCLUDE_BYTES]
        self.allowed = [os.path.realpath(r) for r in allowed_roots]
        self.base = os.path.dirname(conf_path)
        self.limit_hit = False
        self._parse(conf_path, 0)

    def _inside(self, path):
        real = os.path.realpath(path)
        return any(real == a or real.startswith(a + os.sep) for a in self.allowed)

    def _parse(self, path, depth):
        if depth > INCLUDE_DEPTH or self.files >= INCLUDE_FILES:
            self.limit_hit = True
            return
        if not self._inside(path):
            return
        text = _read_limited(path, self.budget)
        if text is None:
            return
        self.files += 1
        for parts in _statements(text):
            name, args = parts[0], parts[1:]
            if name == "user" and args:
                self.users.append(args[0].strip("'\""))
            elif name == "root" and args and "$" not in args[0]:
                self.roots.append(args[0].strip("'\""))
            elif name == "include" and args:
                pattern = args[0].strip("'\"")
                if not pattern.startswith("/"):
                    pattern = os.path.join(self.base, pattern)
                for match in sorted(glob.glob(pattern))[:INCLUDE_FILES]:
                    self._parse(match, depth + 1)


def _proc_scan(proc_dir, comm_prefix, cmd_marker):
    """Executables of running masters: [(pid, exe)] where /proc/<pid>/cmdline starts with the marker."""
    found = []
    try:
        names = os.listdir(proc_dir)
    except OSError:
        return found
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc_dir, name, "comm")) as f:
                comm = f.read(64).strip()
            if not comm.startswith(comm_prefix):
                continue
            with open(os.path.join(proc_dir, name, "cmdline"), "rb") as f:
                cmd = f.read(512).replace(b"\0", b" ").decode("utf-8", "replace")
            if cmd_marker not in cmd:
                continue
            exe = os.readlink(os.path.join(proc_dir, name, "exe"))
        except OSError:
            continue
        found.append((int(name), exe))
    return found


def _strip_deleted(path):
    return path[: -len(" (deleted)")] if path.endswith(" (deleted)") else path


def _unique(items):
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _pool_users(fpm_conf_glob):
    users = []
    for path in sorted(glob.glob(fpm_conf_glob))[:200]:
        text = _read_limited(path, [1024 * 1024])
        if text:
            for m in re.finditer(r"^\s*user\s*=\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$", text, re.MULTILINE):
                users.append(m.group(1))
    return users


def _site_roots(roots):
    """Each nginx root, plus storage/app/public of the site that owns it (the parent of its public directory)."""
    out = []
    for root in roots:
        root = root.rstrip("/") or "/"
        out.append(root)
        if os.path.basename(root) == "public":
            site = os.path.dirname(root)
            link = os.path.join(root, "storage")
            target = os.path.realpath(link) if os.path.islink(link) else os.path.join(site, "storage", "app", "public")
            if os.path.isdir(target):
                out.append(target)
    return _unique(out)


def _vpc(route_text):
    """The private connected route(s) on an interface that does not carry the default route."""
    default_dev = set(re.findall(r"^default .*? dev (\S+)", route_text, re.MULTILINE))
    out = []
    for line in route_text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+) dev (\S+) .*scope link", line)
        if not m or m.group(2) in default_dev:
            continue
        try:
            net = ipaddress.ip_network(m.group(1), strict=True)
        except ValueError:
            continue
        if any(net.subnet_of(p) for p in _PRIVATE):
            out.append(str(net))
    return _unique(out)[:8]


def discover(paths, runner=subprocess.run, webroots=(), nginx_conf=None, fpm_pool_glob=None, which=shutil.which):
    """Everything found, as ({(section, key): text}, [notes]). A missing item is simply absent."""
    found, notes = {}, []
    proc = paths.proc_dir
    # nginx binary: the running master first, then PATH, then `nginx -V` must work
    nginx = ""
    for pid, exe in _proc_scan(proc, "nginx", "nginx: master"):
        nginx = _strip_deleted(exe)
        break
    if not nginx:
        nginx = which("nginx", path="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin") or ""
    conf = nginx_conf
    if nginx:
        version = _run(runner, [nginx, "-V"])
        m = re.search(r"--conf-path=(\S+)", version) if version else None
        conf = conf or (m.group(1) if m else None)
        if not version:
            notes.append("`nginx -V` printed nothing; the binary was found but not confirmed")
        found[("sites", "nginx_bin")] = nginx
    else:
        notes.append("nginx was not found")
    conf = conf or paths._p("/etc/nginx/nginx.conf")
    nginx_roots, users = [], []
    if os.path.exists(conf):
        parsed = NginxConf(conf, allowed_roots=(os.path.dirname(conf),))
        nginx_roots, users = parsed.roots, parsed.users
        if parsed.limit_hit:
            notes.append("nginx include limits were hit; the web roots may be incomplete")
    # php-fpm: running masters (exact binary), then installed ones
    fpm = [_strip_deleted(exe) for _, exe in _proc_scan(proc, "php-fpm", "php-fpm: master")]
    fpm += [p for p in sorted(glob.glob(paths._p("/usr/sbin/php-fpm[0-9]*"))) if os.access(p, os.X_OK)]
    found_fpm = _unique(fpm)
    if found_fpm:
        found[("sites", "phpfpm_bins")] = ",".join(found_fpm)
    cli = [p for p in sorted(glob.glob(paths._p("/usr/bin/php[0-9]*"))) if re.search(r"/php\d+(\.\d+)?$", p) and os.access(p, os.X_OK)]
    if cli:
        found[("sites", "php_cli_bins")] = ",".join(_unique(os.path.realpath(p) for p in cli))
    users += _pool_users(fpm_pool_glob or paths._p("/etc/php/*/fpm/pool.d/*.conf"))
    users = [u for u in _unique(users) if cfgmod._USER_RE.match(u)]
    if users:
        found[("sites", "web_users")] = ",".join(users)
    roots = _site_roots(list(webroots)) if webroots else _site_roots(nginx_roots)
    roots = [r for r in roots if r.startswith("/") and "," not in r and not any(ord(c) < 32 for c in r)]
    if roots:
        found[("sites", "web_roots")] = ",".join(roots)
    vpc = _vpc(_run(runner, ["ip", "-4", "-o", "route", "show"]))
    if vpc:
        found[("sites", "vpc_cidr")] = ",".join(vpc)
    return found, notes


def run_discover(paths, webroots=(), print_only=False, out=print, runner=subprocess.run, **kw):
    """The `discover` subcommand. Exit code: 0 done, 3 refused (nothing written)."""
    cfg = cfgmod.load(paths)
    found, notes = discover(paths, runner=runner, webroots=webroots, **kw)
    for note in notes:
        out("note: " + note)
    for (section, key), value in sorted(found.items()):
        out("%s.%s = %s" % (section, key, value))
    if ("sites", "nginx_bin") not in found and cfg.getbool("kit", "web", True):
        out("refused: no nginx binary was found; install nginx or run with the web part switched off ([kit] web = off)")
        return 3
    if print_only:
        out("print only: local.conf was not changed")
        return 0
    if not paths.dev and os.geteuid() != 0:
        out("refused: discover must run as root to write local.conf")
        return 3
    try:
        cfgmod.update_local_conf(paths, found)
    except (cfgmod.ConfigError, OSError) as e:
        out("refused: %s" % e)
        return 3
    out("wrote %d values to %s" % (len(found), paths.local_conf))
    return 0
