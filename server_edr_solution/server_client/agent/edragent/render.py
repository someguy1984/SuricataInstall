"""Rendering for `edr-agent apply-config` and `edr-agent render` (client PLAN sections 14, 4.3, 4.5 and 4.7).

Pure functions: they read the configuration and the policy templates and write files into a staging
directory. Nothing here touches a target directory, runs a program or reloads anything; apply_config does that.

Staging layout (the same relative paths are used under the target roots):
    tetragon.tp.d/edr-<policy>.yaml                          from tetragon/policies/*.yaml
    systemd/edr-agent.service.d/10-hub.conf                  IPAddressAllow= for the enrolled hub addresses (none in local mode)
    edr-agent/notify.min_severity                            the severity edr-notify may send (it cannot read local.conf)

The placeholder rule of the templates: a line holding @NAME@ is repeated once per value and left out when the
value list is empty. Policies of a component switched off in [kit] are left out, and so is a policy whose
rendering would leave a list empty. A rendered policy is checked again before it is written: no @...@ left, it
parses (with the small parser below: the agent is standard library only), and it stays inside the limits tests/lint.sh enforces: 5 selectors, 5 args and 3
actions a hook, 8 prefix or postfix lists and 8 exact-match lists a policy, one kprobe a symbol, and 64
followChildren paths shared by all policies. A policy that would break a limit is refused with the key named,
never written, because Tetragon would reject it (and a rejected enforcing policy is lost enforcement).
"""
import glob
import json
import os
import re

PLACEHOLDER_RE = re.compile(r"@([A-Z_]+)@")
WEB_PLACEHOLDERS = {"NGINX_BIN", "PHPFPM_BIN", "PHP_CLI_BIN", "WEB_EXEC_ALLOW"}
SENDMAIL = "/usr/sbin/sendmail"
FOLLOW_IDS_MAX = 64
MAX_LIST_VALUES = 64
POLICY_PREFIX = "edr-"
PREFIX_OPS = ("Prefix", "NotPrefix", "Postfix", "NotPostfix")


class RenderError(Exception):
    """A refusal: `key` names the configuration key to look at ('[sites] phpfpm_bins'), '' when it is the template."""

    def __init__(self, key, message):
        super().__init__("%s: %s" % (key, message) if key else message)
        self.key, self.message = key, message


# ---- values ----------------------------------------------------------------------------------------
def _unique(items):
    out, seen = [], set()
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def tetragon_values(cfg):
    """{placeholder: [value, ...]} from [sites] and [tetragon]."""
    nginx = [cfg.get("sites", "nginx_bin", "")]
    fpm = cfg.getlist("sites", "phpfpm_bins")
    cli = cfg.getlist("sites", "php_cli_bins")
    allow = _unique(fpm + nginx + [SENDMAIL] + cfg.getlist("tetragon", "web_exec_allow"))
    values = {"NGINX_BIN": _unique(nginx), "PHPFPM_BIN": _unique(fpm), "PHP_CLI_BIN": _unique(cli),
              "WEB_EXEC_ALLOW": allow, "EGRESS_PORTS_EXTRA": _unique(cfg.getlist("tetragon", "egress_ports")),
              "VPC_CIDR": _unique(cfg.getlist("sites", "vpc_cidr"))}
    keys = {"PHPFPM_BIN": "[sites] phpfpm_bins", "PHP_CLI_BIN": "[sites] php_cli_bins", "WEB_EXEC_ALLOW": "[tetragon] web_exec_allow",
            "EGRESS_PORTS_EXTRA": "[tetragon] egress_ports"}
    for name, key in keys.items():
        if len(values[name]) > MAX_LIST_VALUES:
            raise RenderError(key, "%d entries; a policy list holds at most %d" % (len(values[name]), MAX_LIST_VALUES))
    return values


def _quote(value):
    """The value as it goes between the double quotes of a YAML scalar."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_text(text, values):
    """The documented rule: a line holding a placeholder is repeated once per value and left out without one.
    Placeholders in comments stay as words (the @ signs go), so a rendered file holds no @...@."""
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("#"):
            out.append(PLACEHOLDER_RE.sub(r"\1", line))
            continue
        names = PLACEHOLDER_RE.findall(line)
        if not names:
            out.append(line)
            continue
        if len(set(names)) > 1:
            raise RenderError("", "a template line holds two placeholders: %s" % line.strip())
        name = names[0]
        for v in values.get(name, []):
            out.append(line.replace("@%s@" % name, _quote(v)))
    return "\n".join(out)


def placeholders_used(text):
    return {n for line in text.split("\n") if not line.lstrip().startswith("#") for n in PLACEHOLDER_RE.findall(line)}


# ---- a small parser for the YAML subset the policy templates use -------------------------------------
# Block maps and lists, "double quoted" and plain scalars, numbers, booleans, [flow, lists] and # comments. Not YAML in
# general: a template that needs more is refused ("does not parse") rather than guessed at.
_KEY_RE = re.compile(r"^([A-Za-z0-9_.-]+):(?:\s+(.*))?$")


def _strip_comment(line):
    in_q = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_q:
            if c == "\\":
                i += 1
            elif c == '"':
                in_q = False
        elif c == '"':
            in_q = True
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
        i += 1
    return line.rstrip()


def _scalar(text):
    text = text.strip()
    if text.startswith('"'):
        if not text.endswith('"') or len(text) < 2:
            raise ValueError("unterminated string")
        return json.loads(text)
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError("unterminated list")
        inner = text[1:-1].strip()
        return [_scalar(p) for p in _split_flow(inner)] if inner else []
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if text[0] in "{|>&*!'":
        raise ValueError("unsupported YAML: " + text[:20])
    return text


def _split_flow(inner):
    parts, cur, in_q, i = [], "", False, 0
    while i < len(inner):
        c = inner[i]
        if in_q:
            cur += c
            if c == "\\" and i + 1 < len(inner):
                i += 1
                cur += inner[i]
            elif c == '"':
                in_q = False
        elif c == '"':
            in_q = True
            cur += c
        elif c == ",":
            parts.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    parts.append(cur)
    return parts


def parse_policy(text):
    """The document of a policy file as dicts, lists and scalars. Raises ValueError."""
    lines = []
    for raw in text.split("\n"):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ValueError("a tab in the indentation")
        line = _strip_comment(raw)
        if line.strip():
            lines.append((len(line) - len(line.lstrip(" ")), line.strip()))
    if not lines:
        raise ValueError("empty")
    value, i = _block(lines, 0, lines[0][0])
    if i != len(lines):
        raise ValueError("unexpected indentation near: " + lines[i][1][:40])
    return value


def _block(lines, i, indent):
    if lines[i][1].startswith("- ") or lines[i][1] == "-":
        return _list(lines, i, indent)
    return _map(lines, i, indent)


def _list(lines, i, indent):
    out = []
    while i < len(lines) and lines[i][0] == indent and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
        rest = lines[i][1][1:]
        content = rest.lstrip(" ")
        offset = 1 + len(rest) - len(content)
        if not content:
            i += 1
            if i < len(lines) and lines[i][0] > indent:
                val, i = _block(lines, i, lines[i][0])
            else:
                val = None
            out.append(val)
        elif _KEY_RE.match(content):
            lines = lines[:i] + [(indent + offset, content)] + lines[i + 1:]
            val, i = _map(lines, i, indent + offset)
            out.append(val)
        else:
            out.append(_scalar(content))
            i += 1
    return out, i


def _map(lines, i, indent):
    out = {}
    while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
        m = _KEY_RE.match(lines[i][1])
        if not m:
            raise ValueError("not a key: " + lines[i][1][:40])
        key, rest = m.group(1), m.group(2)
        if key in out:
            raise ValueError("duplicate key " + key)
        i += 1
        if rest is not None and rest.strip():
            out[key] = _scalar(rest)
        elif i < len(lines) and (lines[i][0] > indent or (lines[i][0] == indent and lines[i][1].startswith("- "))):
            out[key], i = _block(lines, i, lines[i][0])
        else:
            out[key] = None
    return out, i


# ---- checks ----------------------------------------------------------------------------------------
def empty_list_in_text(text):
    """True when a `values:` list has no items (a policy Tetragon would reject, or one that matches nothing)."""
    lines = [l for l in text.split("\n") if l.strip() and not l.lstrip().startswith("#")]
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "values: []":
            return True
        if s == "values:":
            nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if not nxt.startswith("- "):
                return True
    return False


def analyse(doc):
    """(problems, follow_children_values) for one parsed policy."""
    problems, follow, symbols = [], set(), []
    prefix = equal = 0
    for hook in (doc.get("spec") or {}).get("kprobes") or []:
        call = hook.get("call", "?")
        symbols.append(call)
        sels = hook.get("selectors") or []
        if len(sels) > 5:
            problems.append("%s: %d selectors (Tetragon allows 5)" % (call, len(sels)))
        if len(hook.get("args") or []) > 5:
            problems.append("%s: more than 5 args" % call)
        for sel in sels:
            if len(sel.get("matchActions") or []) > 3:
                problems.append("%s: more than 3 actions in one selector" % call)
            for m in sel.get("matchArgs") or []:
                prefix += m.get("operator") in PREFIX_OPS
                equal += m.get("operator") in ("Equal", "NotEqual") and any(not str(v).lstrip("-").isdigit() for v in m.get("values") or [])
                if not m.get("values"):
                    problems.append("%s: an empty values list" % call)
            for m in sel.get("matchBinaries") or []:
                prefix += m.get("operator") in PREFIX_OPS
                if not m.get("values"):
                    problems.append("%s: an empty binaries list" % call)
                if m.get("followChildren"):
                    follow.update(str(v) for v in m.get("values") or [])
    if len(symbols) != len(set(symbols)):
        problems.append("two kprobes on one symbol")
    if prefix > 8:
        problems.append("%d prefix/postfix lists (Tetragon allows 8 per policy)" % prefix)
    if equal > 8:
        problems.append("%d exact-match string lists (Tetragon allows 8 per policy)" % equal)
    return problems, follow


def check_policy(name, text):
    """(problems, follow_ids) for one rendered file. name None skips the metadata.name comparison."""
    problems = []
    if PLACEHOLDER_RE.search(text):
        problems.append("a placeholder is left")
    try:
        doc = parse_policy(text)
    except ValueError as e:
        return problems + ["does not parse: %s" % e], set()
    if not isinstance(doc, dict) or doc.get("kind") != "TracingPolicy":
        return problems + ["is not a TracingPolicy"], set()
    if name is not None and (doc.get("metadata") or {}).get("name") != name:
        problems.append("metadata.name is not %s" % name)
    more, follow = analyse(doc)
    return problems + more, follow


# ---- policies --------------------------------------------------------------------------------------
def _policy_files(template_dir):
    return sorted(glob.glob(os.path.join(template_dir, "*.yaml")))


def render_policies(template_dir, cfg):
    """({file name: text}, {policy: reason it was left out}, notes). Raises RenderError on a refusal."""
    out, skipped, notes = {}, {}, []
    files = _policy_files(template_dir)
    if not files:
        raise RenderError("", "no policy templates in %s" % template_dir)
    if not cfg.getbool("kit", "tetragon", True):
        return out, {os.path.basename(p)[:-5]: "[kit] tetragon is off" for p in files}, notes
    values = tetragon_values(cfg)
    follow_total = 0
    for path in files:
        name = os.path.basename(path)[:-5]
        with open(path, encoding="utf-8") as f:
            text = f.read()
        used = placeholders_used(text)
        if used & {"NGINX_BIN", "PHPFPM_BIN", "PHP_CLI_BIN"} and not cfg.getbool("kit", "web", True):
            skipped[name] = "[kit] web is off"
            continue
        rendered = render_text(text, values)
        problems, follow = check_policy(name, rendered)
        empties = [p for p in problems if "empty" in p]
        if empties:
            missing = sorted(n for n in used if not values.get(n) and n in ("NGINX_BIN", "PHPFPM_BIN", "PHP_CLI_BIN"))
            why = "no value for %s (run edr-agent discover)" % ", ".join("@%s@" % n for n in missing) if missing else empties[0]
            skipped[name] = why
            continue
        if problems:
            raise RenderError("", "policy %s: %s" % (name, "; ".join(problems)))
        follow_total += len(follow)
        if follow_total > FOLLOW_IDS_MAX:
            raise RenderError("[sites] phpfpm_bins", "the policies would follow %d binary paths with followChildren (Tetragon shares %d ids); "
                              "list fewer php-fpm binaries (policy %s pushed it over)" % (follow_total, FOLLOW_IDS_MAX, name))
        out["%s.yaml" % (name if name.startswith(POLICY_PREFIX) else POLICY_PREFIX + name)] = rendered if rendered.endswith("\n") else rendered + "\n"
    return out, skipped, notes


# ---- the drop-in and the notify credential ----------------------------------------------------------
def hub_addresses(paths):
    """The enrolled hub addresses from identity/current/hub.conf, or [] in local mode."""
    cur = os.path.join(paths.identity_dir, "current")
    if not os.path.exists(cur):
        return []
    try:
        from .identity import read_hub_conf
        hc = read_hub_conf(os.path.join(os.path.realpath(cur), "hub.conf"))
    except ImportError:
        hc = None
    return list(hc["addresses"]) if hc else []


def render_dropin(addresses):
    """The IPAddressAllow= drop-in text, or None in local mode (no hub address: the unit denies every address)."""
    if not addresses:
        return None
    return "[Service]\nIPAddressAllow=\nIPAddressAllow=%s\n" % " ".join(addresses)


def render_notify_severity(cfg):
    return cfg.get("notify", "min_severity", "HIGH") + "\n"


# ---- everything --------------------------------------------------------------------------------------
# relative path in the staging directory -> (mode)
MODES = {"tetragon.tp.d": 0o600, "systemd": 0o644, "edr-agent": 0o600}


def render_all(paths, cfg, template_dir=None):
    """({relative path: text}, skipped, notes). Raises RenderError."""
    template_dir = template_dir or paths.policy_templates
    policies, skipped, notes = render_policies(template_dir, cfg)
    files = {"tetragon.tp.d/" + n: t for n, t in policies.items()}
    drop = render_dropin(hub_addresses(paths))
    if drop is not None:
        files["systemd/edr-agent.service.d/10-hub.conf"] = drop
    files["edr-agent/notify.min_severity"] = render_notify_severity(cfg)
    return files, skipped, notes


def mode_of(relative):
    return MODES.get(relative.split("/", 1)[0], 0o644)


def write_staging(files, out_dir):
    """Write rendered files under out_dir. Returns the list of paths written."""
    written = []
    for rel, text in sorted(files.items()):
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode_of(rel))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        written.append(path)
    return written
