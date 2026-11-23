"""local.conf and defaults.conf: strict parsing, the last good copy, apply-config (client PLAN section 14).

One INI file holds every choice that changes what the kit detects, bans, forwards or enforces. It is
read with configparser (no interpolation, duplicates are an error). Unknown sections and keys, wrong
types and out-of-range values are refused with the key named. Precedence: local.conf over
defaults.conf over the built-in table below, so a missing defaults.conf is not fatal.

Typed values (what Config.get returns):
    bool        True or False                    (on/off, true/false, yes/no, 1/0)
    enum        the string                       (for example auto_ban: "on", "observe", "off")
    int         int
    dur         seconds, int                     (30s 10m 1h 7d)
    size        bytes, int                       (64M 4G); size_off: 0 means "off"
    rate        (count, seconds)                 ("5/10m" gives (5, 600))
    list        list of normalised strings       (comma separated; "ban_ladder" is a list of seconds)
"""
import configparser
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import time

CONF_MAX_BYTES = 256 * 1024

_DUR_RE = re.compile(r"^(\d{1,9})([smhd])$")
_SIZE_RE = re.compile(r"^(\d{1,12})\s*([KMGT]?)(?:i?B)?$", re.IGNORECASE)
_RATE_RE = re.compile(r"^(\d{1,6})\s*(?:/|per)\s*(\d{1,9}[smhd])$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_BOOL = {"on": True, "true": True, "yes": True, "1": True, "off": False, "false": False, "no": False, "0": False}
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_SIZE_UNIT = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}


class ConfigError(ValueError):
    pass


# ---- value parsers: each takes the text and returns the typed value, or raises ConfigError ----------
def _dur(text):
    m = _DUR_RE.match(text)
    if not m:
        raise ConfigError("not a duration (use 30s, 10m, 1h or 7d)")
    secs = int(m.group(1)) * _UNIT[m.group(2)]
    if secs < 1 or secs > 366 * 86400:
        raise ConfigError("duration out of range")
    return secs


def _size(text):
    m = _SIZE_RE.match(text)
    if not m:
        raise ConfigError("not a size (use 64M or 4G)")
    return int(m.group(1)) * _SIZE_UNIT[m.group(2).upper()]


def _size_off(text):
    if text.lower() in ("off", "no", "0", ""):
        return 0
    return _size(text)


def _rate(text):
    m = _RATE_RE.match(text.strip())
    if not m:
        raise ConfigError("not a rate (use 5/10m)")
    count, secs = int(m.group(1)), _dur(m.group(2))
    if count < 1:
        raise ConfigError("count must be at least 1")
    return (count, secs)


def _bool(text):
    try:
        return _BOOL[text.lower()]
    except KeyError:
        raise ConfigError("not on or off") from None


def _bool_or_empty(text):
    return None if text == "" else _bool(text)


def _int_range(lo, hi):
    def parse(text):
        try:
            value = int(text, 10)
        except ValueError:
            raise ConfigError("not a whole number") from None
        if not lo <= value <= hi:
            raise ConfigError("out of range %d to %d" % (lo, hi))
        return value
    return parse


def _enum(*choices):
    def parse(text):
        if text not in choices:
            raise ConfigError("must be one of: " + ", ".join(c or "(empty)" for c in choices))
        return text
    return parse


def _str(text):
    if len(text) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ConfigError("not a plain one-line value")
    return text


def _abspath(text):
    text = _str(text)
    if text and not text.startswith("/"):
        raise ConfigError("not an absolute path")
    if "\x00" in text or ".." in text.split("/"):
        raise ConfigError("not a clean absolute path")
    return text


def _web_path(text):
    text = _str(text)
    if text and not text.startswith("/"):
        raise ConfigError("must start with /")
    return text


def _user(text):
    if not _USER_RE.match(text):
        raise ConfigError("not a user name")
    return text


def _name(text):
    if not _NAME_RE.match(text):
        raise ConfigError("not a plain name")
    return text


def _host(text):
    if not _HOST_RE.match(text):
        raise ConfigError("not a host name")
    return text


def _ip(text):
    if text != text.strip() or "%" in text or not text:
        raise ConfigError("not an IP address")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ConfigError("not an IP address") from None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _cidr(text):
    if text != text.strip() or "%" in text or not text:
        raise ConfigError("not a CIDR")
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as e:
        raise ConfigError("not a clean CIDR (%s)" % e) from None
    return str(net)


def _ipnet(text):
    return _cidr(text)


def _port(text):
    return str(_int_range(1, 65535)(text))


def _split(text):
    return [part.strip() for part in re.split(r"[,\n]", text) if part.strip()]


def _list(item, max_items=1024):
    def parse(text):
        out = []
        for part in _split(text):
            out.append(item(part))
        if len(out) > max_items:
            raise ConfigError("more than %d entries" % max_items)
        return out
    parse.is_list = True
    return parse


def _home_net(text):
    if text.strip().lower() in ("", "auto"):
        return []
    return _list(_cidr)(text)


_home_net.is_list = True


# (section, key, parser, default text, can hold a continuation line)
_SCHEMA = [
    ("sites", "web_users", _list(_user), ""),
    ("sites", "web_roots", _list(_abspath), ""),
    ("sites", "nginx_bin", _abspath, ""),
    ("sites", "phpfpm_bins", _list(_abspath), ""),
    ("sites", "php_cli_bins", _list(_abspath), ""),
    ("sites", "vpc_cidr", _list(_cidr, 8), ""),
    ("sites", "extra_addresses", _list(_ip, 64), ""),
    ("bans", "admin_ip", _list(_ipnet, 64), ""),
    ("bans", "allow_cidr", _list(_cidr, 4096), ""),
    ("bans", "auto_ban", _enum("on", "observe", "off"), "on"),
    ("bans", "hub_bans", _bool, "on"),
    ("bans", "feeds", _bool, "on"),
    ("bans", "proxy_mode", _enum("auto", "on", "off"), "auto"),
    ("bans", "bigconn_bytes", _size, "4G"),
    ("bans", "bigconn_cap", _size_off, "off"),
    ("thresholds", "ssh_fail", _rate, "5/10m"),
    ("thresholds", "tripwire", _rate, "5/5m"),
    ("thresholds", "suricata", _rate, "3/10m"),
    ("thresholds", "window_update", _rate, "3/10m"),
    ("thresholds", "bigconn_repeat", _rate, "2/1h"),
    ("thresholds", "suricata_sigs", _rate, "2/10m"),
    ("thresholds", "ban_budget_per_hour", _int_range(0, 10000), "30"),
    ("thresholds", "ban_max_active", _int_range(1, 10000), "1000"),
    ("thresholds", "ban_ladder", _list(_dur, 16), "1h,6h,24h,7d"),
    ("thresholds", "ban_memory", _dur, "14d"),
    ("tetragon", "enforce", _list(_name, 64), "nginx-exec,sctp-socket"),
    ("tetragon", "egress_ports", _list(_port, 256), ""),
    ("tetragon", "web_exec_allow", _list(_abspath, 512), ""),
    ("suricata", "lite", _bool, "off"),
    ("suricata", "sslbl", _bool, "off"),
    ("suricata", "home_net", _home_net, "auto"),
    ("kernel", "sctp_block", _bool, "on"),
    ("kit", "web", _bool, "on"),
    ("kit", "tetragon", _bool, "on"),
    ("kit", "suricata", _bool, "on"),
    ("kit", "kernel", _bool, "on"),
    ("diskguard", "stop_suricata", _bool, "on"),
    ("dns", "lockdown", _bool, "on"),
    ("dns", "lock_forwarded", _bool, "off"),
    ("dns", "block_doh_ips", _bool, "off"),
    ("dns", "vpc_dns", _enum("off", "auto", "on"), "off"),
    ("dns", "resolve_check", _list(_host, 32), ""),
    ("agent", "redact", _bool, "on"),
    ("agent", "payload", _enum("hex-head", "off"), "hex-head"),
    ("agent", "args", _enum("redact", "drop"), "redact"),
    ("agent", "event_budget_per_hour", _int_range(1, 1000000), "2000"),
    ("agent", "access_ring_minutes", _int_range(1, 60), "5"),
    ("agent", "access_ring_lines", _int_range(100, 200000), "20000"),
    ("agent", "nginx_info_log", _bool, "off"),
    ("agent", "laravel_log", _abspath, ""),
    ("agent", "login_route", _web_path, ""),
    ("agent", "sshd_password_auth", _bool_or_empty, ""),
    ("agent", "dns_telemetry", _bool, "on"),
    ("agent", "rehome_confirm_timeout", _dur, "300s"),
    ("notify", "min_severity", _enum("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"), "HIGH"),
    ("response", "auto_restart_nginx", _bool, "false"),
    ("isolate", "allow", _list(_ipnet, 256), ""),
]
SCHEMA = {(s, k): (p, d) for s, k, p, d in _SCHEMA}
SECTIONS = sorted({s for s, _ in SCHEMA})


def key_name(section, key):
    return "[%s] %s" % (section, key)


def _new_parser():
    parser = configparser.ConfigParser(
        interpolation=None, strict=True, delimiters=("=",), comment_prefixes=("#",),
        inline_comment_prefixes=None, default_section="__edr_no_default__", allow_no_value=False,
        empty_lines_in_values=False)
    parser.optionxform = str       # keys are case sensitive: "Web_Users" is unknown
    return parser


def parse_text(text, label):
    """Parse one file's text. Returns ({(section, key): raw}, [errors]). Never raises."""
    errors, raw = [], {}
    parser = _new_parser()
    try:
        parser.read_string(text, source=label)
    except configparser.Error as e:
        return {}, ["%s: %s" % (label, " ".join(str(e).split()))]
    for section in parser.sections():
        if section not in SECTIONS:
            errors.append("%s: unknown section [%s]" % (label, section))
            continue
        for key, value in parser.items(section):
            if (section, key) not in SCHEMA:
                errors.append("%s: unknown key %s" % (label, key_name(section, key)))
                continue
            raw[(section, key)] = value.strip()
    return raw, errors


def parse_value(section, key, text):
    """The typed value of one key's text; raises ConfigError naming the key."""
    parser, _ = SCHEMA[(section, key)]
    text = text.strip()
    if "\n" in text and not _is_list(section, key):
        raise ConfigError("%s: a single value only" % key_name(section, key))
    try:
        return parser(text)
    except ConfigError as e:
        raise ConfigError("%s: %s" % (key_name(section, key), e)) from None


def _is_list(section, key):
    return getattr(SCHEMA[(section, key)][0], "is_list", False)


def _read_file(path):
    """The text of a config file, or None when missing. Oversized or odd files are an error string."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, "%s: cannot be read (%s)" % (path, e.strerror)
    try:
        st = os.fstat(fd)
        if not os.path.isfile(path) or st.st_size > CONF_MAX_BYTES:
            return None, "%s: not a regular file or over %d bytes" % (path, CONF_MAX_BYTES)
        data = os.read(fd, CONF_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > CONF_MAX_BYTES:
        return None, "%s: over %d bytes" % (path, CONF_MAX_BYTES)
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "%s: not UTF-8" % path


class Config:
    """The effective, typed configuration. Created by load() or defaults()."""

    def __init__(self):
        self.raw = {k: d for k, (_, d) in SCHEMA.items()}
        self.origin = {k: "builtin" for k in SCHEMA}
        self.errors = []            # problems found in local.conf (the agent raises health.config_invalid)
        self.warnings = []
        self.state = "defaults"     # "local", "last-good" or "defaults": what the values come from
        self.sha256 = hashlib.sha256(b"").hexdigest()   # of local.conf as read (heartbeat local_conf_sha256)
        self._typed = {}
        self._retype()

    # ---- reading values -------------------------------------------------------------------
    def _retype(self):
        typed = {}
        for (section, key), text in self.raw.items():
            try:
                typed[(section, key)] = parse_value(section, key, text)
            except ConfigError:
                parser, default = SCHEMA[(section, key)]
                typed[(section, key)] = parser(default)
                self.raw[(section, key)] = default
        self._typed = typed

    def get(self, section, key, default=None):
        return self._typed.get((section, key), default)

    def getbool(self, section, key, default=False):
        return bool(self._typed.get((section, key), default))

    def getint(self, section, key, default=0):
        return int(self._typed.get((section, key), default))

    def getlist(self, section, key):
        value = self._typed.get((section, key), [])
        return list(value) if isinstance(value, (list, tuple)) else [value]

    def __getitem__(self, section):
        return {k: v for (s, k), v in self._typed.items() if s == section}

    def __contains__(self, item):
        return item in SECTIONS if isinstance(item, str) else item in self._typed

    @property
    def invalid(self):
        return bool(self.errors)

    def effective(self):
        """{ "section.key": raw text } for every key, for printing and diffs."""
        return {"%s.%s" % k: v for k, v in sorted(self.raw.items())}

    def update_from(self, other):
        """Take another Config's values in place, so objects holding this one see the change."""
        self.raw, self.origin = dict(other.raw), dict(other.origin)
        self.errors, self.warnings, self.state, self.sha256 = other.errors, other.warnings, other.state, other.sha256
        self._typed = dict(other._typed)


def defaults():
    return Config()


def _apply(cfg, raw, origin, errors):
    """Put the raw values of one file into cfg when each one is valid; collect the errors."""
    for (section, key), text in raw.items():
        try:
            parse_value(section, key, text)
        except ConfigError as e:
            errors.append(str(e))
            continue
        cfg.raw[(section, key)] = text
        cfg.origin[(section, key)] = origin


def load(paths, save_good=False):
    """defaults.conf then local.conf over the built-in table.

    A bad local.conf is not used: the last good copy is (and if that is gone, the defaults), and the errors
    stay in cfg.errors so the agent can raise health.config_invalid. save_good keeps the copy of a valid
    local.conf in the state directory (the agent does this; apply-config --check does not).
    """
    cfg = Config()
    problems = []
    text, err = _read_file(paths.defaults_conf)
    if err:
        cfg.warnings.append(err)
    elif text is not None:
        raw, errors = parse_text(text, "defaults.conf")
        _apply(cfg, raw, "defaults.conf", cfg.warnings)
        cfg.warnings.extend(errors)

    local_text, err = _read_file(paths.local_conf)
    if err:
        problems.append(err)
    if local_text is not None:
        cfg.sha256 = hashlib.sha256(local_text.encode("utf-8")).hexdigest()
        raw, errors = parse_text(local_text, "local.conf")
        problems.extend(errors)
        trial = Config()
        trial.raw, trial.origin = dict(cfg.raw), dict(cfg.origin)
        _apply(trial, raw, "local.conf", problems)
        if not problems:
            cfg.raw, cfg.origin, cfg.state = trial.raw, trial.origin, "local"
            if save_good:
                _save_good(paths, local_text)
    if problems:
        cfg.errors = problems
        good, _ = _read_file(paths.config_good)
        if good is not None:
            raw, errors = parse_text(good, "local.conf.good")
            trial_errors = list(errors)
            trial = Config()
            trial.raw, trial.origin = dict(cfg.raw), dict(cfg.origin)
            _apply(trial, raw, "last-good", trial_errors)
            if not trial_errors:
                cfg.raw, cfg.origin, cfg.state = trial.raw, trial.origin, "last-good"
    cfg._retype()
    return cfg


def _save_good(paths, text):
    try:
        old, _ = _read_file(paths.config_good)
        if old == text:
            return
        os.makedirs(paths.state_dir, mode=0o700, exist_ok=True)
        tmp = paths.config_good + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, paths.config_good)
    except OSError:
        pass        # the copy is a convenience; a read-only state directory must not stop the agent


def diff(old, new):
    """[(key, old text, new text)] for every key whose effective value differs."""
    out = []
    for k in sorted(SCHEMA):
        if old.raw.get(k) != new.raw.get(k):
            out.append(("%s.%s" % k, old.raw.get(k), new.raw.get(k)))
    return out


def set_key_in_text(text, section, key, value):
    """Return text with `key = value` set inside [section], keeping every other line as it is."""
    lines = text.splitlines()
    header = "[%s]" % section
    start = None
    for i, line in enumerate(lines):
        if line.strip() == header:
            start = i
            break
    new_line = "%s = %s" % (key, value)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([header, new_line])
        return "\n".join(lines) + "\n"
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].strip().startswith("["):
            end = i
            break
    for i in range(start + 1, end):
        stripped = lines[i].strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        if stripped.split("=", 1)[0].strip() == key:
            lines[i] = new_line
            return "\n".join(lines) + "\n"
    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines.insert(insert_at, new_line)
    return "\n".join(lines) + "\n"


def write_text_atomic(path, text, mode=0o640):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def update_local_conf(paths, changes):
    """Write {(section, key): value text} into local.conf, validating each value first. Returns the new text."""
    for (section, key), value in changes.items():
        if (section, key) not in SCHEMA:
            raise ConfigError("unknown key %s" % key_name(section, key))
        parse_value(section, key, value)
    text, err = _read_file(paths.local_conf)
    if err:
        raise ConfigError(err)
    text = text or ""
    for (section, key), value in changes.items():
        text = set_key_in_text(text, section, key, value)
    write_text_atomic(paths.local_conf, text, 0o640)
    return text


# ---- apply-config ----------------------------------------------------------------------------------
def _fpm_version(binary):
    m = re.search(r"php-fpm(\d+(?:\.\d+)?)", binary)
    return m.group(1) if m else ""


def _read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _install_file(path, text, mode):
    """Atomic replace of one file: a temporary name in the same directory, fsync, rename."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    tmp = os.path.join(directory, ".edr-new-" + os.path.basename(path))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _target_roots(paths):
    """Where each staging subdirectory lands."""
    return {"tetragon.tp.d": paths.tetragon_tp_dir,
            "systemd/edr-agent.service.d": os.path.dirname(paths.dropin_path),
            "edr-agent": paths.etc_dir}


def _target_of(paths, rel):
    for prefix, root in _target_roots(paths).items():
        if rel.startswith(prefix + "/"):
            return os.path.join(root, rel[len(prefix) + 1:])
    raise ValueError("no target for " + rel)


def plan_swap(paths, files):
    """[(relative, target, status, new text, old text)] with status new, changed or same, and the stale
    policy files (rendered earlier, left out now) as status remove."""
    plan = []
    for rel, text in sorted(files.items()):
        target = _target_of(paths, rel)
        old = _read_text(target)
        plan.append((rel, target, "new" if old is None else "same" if old == text else "changed", text, old))
    tp = paths.tetragon_tp_dir
    wanted = {os.path.basename(t) for r, t, *_ in plan if r.startswith("tetragon.tp.d/")}
    try:
        names = sorted(os.listdir(tp))
    except OSError:
        names = []
    for n in names:
        if n.startswith("edr-") and n.endswith(".yaml") and n not in wanted:
            plan.append(("tetragon.tp.d/" + n, os.path.join(tp, n), "remove", None, _read_text(os.path.join(tp, n))))
    return plan


def _follows_children(text):
    return bool(text) and "followChildren: true" in text


def apply_config(paths, check_only=False, out=print, kill=os.kill, runner=subprocess.run, sleep=time.sleep):
    """Validate local.conf, render, show what changes, swap and reload. Returns the exit code.

    0 done, 2 the swap or a reload failed (the files are put back when the swap fails), 3 refused: nothing changed.
    Under EDR_AGENT_ROOT the reload commands are printed, never run. php-fpm is never restarted: the command is printed.
    """
    from . import render
    cfg = load(paths)
    if cfg.errors:
        out("refused: local.conf is not valid; the running configuration is kept")
        for e in cfg.errors:
            out("  " + e)
        return 3
    try:
        files, skipped, notes = render.render_all(paths, cfg)
    except (render.RenderError, OSError) as e:
        out("refused: %s; the running configuration is kept" % e)
        return 3
    running = Config()
    good, _ = _read_file(paths.config_good)
    if good is not None:
        raw, errors = parse_text(good, "local.conf.good")
        if not errors:
            _apply(running, raw, "last-good", [])
            running._retype()
    changes = diff(running, cfg)
    if check_only:
        out("effective values:")
        for k, v in cfg.effective().items():
            out("  %s = %s%s" % (k, v, "" if cfg.origin[tuple(k.split(".", 1))] != "local.conf" else "   (local.conf)"))
    for name, old, new in changes:
        out("changed: %s %s -> %s" % (name, old if old != "" else "(empty)", new if new != "" else "(empty)"))
    if not changes:
        out("no change")
    for w in cfg.warnings:
        out("warning: " + w)
    plan = plan_swap(paths, files)
    todo = [p for p in plan if p[2] != "same"]
    for rel, target, status, _, _ in todo:
        out("%s: %s" % ({"new": "new file", "changed": "changed file", "remove": "removed file"}[status], target))
    for name, why in sorted(skipped.items()):
        out("left out: policy %s (%s)" % (name, why))
    for n in notes:
        out("note: " + n)
    if check_only:
        out("check only: nothing was changed")
        return 0
    if not paths.dev and os.geteuid() != 0:
        out("refused: apply-config must run as root")
        return 3
    staging = tempfile.mkdtemp(prefix="edr-render-")
    try:
        render.write_staging(files, staging)
        done = []
        try:
            for rel, target, status, text, old in todo:
                if status == "remove":
                    os.unlink(target)
                else:
                    _install_file(target, text, render.mode_of(rel))
                done.append((target, old))
        except OSError as e:
            for target, old in reversed(done):          # put back what was there
                try:
                    if old is None:
                        os.unlink(target)
                    else:
                        _install_file(target, old, 0o600)
                except OSError:
                    pass
            out("failed: %s; the previous files were put back" % e)
            return 2
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    text, _ = _read_file(paths.local_conf)
    if text is not None:
        _save_good(paths, text)
    policy_changed = [p for p in todo if p[0].startswith("tetragon.tp.d/")]
    dropin_changed = any(p[0].startswith("systemd/") for p in todo)
    code = _reload(paths, bool(policy_changed), dropin_changed, bool(changes), out, kill, runner, sleep)
    if any(_follows_children(p[3]) or _follows_children(p[4]) for p in policy_changed):
        bins = cfg.get("sites", "phpfpm_bins")
        units = " ".join("php%s-fpm" % _fpm_version(b) for b in bins) if bins else "<your php-fpm units>"
        out("a policy that follows children changed: restart (not reload) php-fpm for it to apply:")
        out("  systemctl restart " + units)
        out("  nothing here runs it for you")
    return code


def _reload(paths, policies, dropin, conf, out, kill, runner, sleep):
    """Reload what changed. Tetragon watches its policy directory, so a policy needs no command: it is
    checked with `tetra tracingpolicy list`. Under a dev root the commands are only printed."""
    commands = []
    if dropin:
        commands += [["systemctl", "daemon-reload"], ["systemctl", "restart", "edr-agent.service"]]
    if policies:
        commands.append(["tetra", "tracingpolicy", "list"])
    code = 0
    for argv in commands:
        if paths.dev:
            out("would run: " + " ".join(argv))
            continue
        out("running: " + " ".join(argv))
        try:
            if argv[0] == "tetra":
                sleep(5)                                # the watcher loads the files within a few seconds
            p = runner(argv, capture_output=True, text=True, timeout=60, check=False)
            if p.returncode != 0:
                out("failed: %s (exit %d)" % (" ".join(argv), p.returncode))
                code = 2
            elif argv[0] == "tetra":
                out((p.stdout or "").rstrip())
        except (OSError, subprocess.SubprocessError) as e:
            out("failed: %s (%s)" % (" ".join(argv), e))
            code = 2
    if conf and not dropin:
        _signal_agent(paths, kill, out)
    return code


def _signal_agent(paths, kill, out):
    """Tell a running agent to re-read local.conf (SIGHUP to the pid in its run directory)."""
    try:
        with open(paths.pid_file) as f:
            pid = int(f.read(32).strip())
        if pid > 1:
            kill(pid, 1)
            out("signalled the running agent to re-read local.conf")
    except (OSError, ValueError):
        pass
