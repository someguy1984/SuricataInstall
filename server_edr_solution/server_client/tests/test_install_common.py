"""Shared fixtures for the install.sh and uninstall.sh tests. Neither script is ever run
for real: only `--plan`, usage errors and the pure helpers. A test root (EDR_AGENT_ROOT) replaces every path the
pre-flight reads and every program it asks (files in ROOT/probe/), and a stub directory first on PATH logs any
call of a command that could change the machine: the log must stay empty."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.realpath(__file__))
CLIENT = os.path.dirname(HERE)
INSTALL = os.path.join(CLIENT, "install.sh")
UNINSTALL = os.path.join(CLIENT, "uninstall.sh")
FILES = os.path.join(CLIENT, "files")
# every command that could change the machine, plus the read-only ones the plan must not need to run for real
STUBS = ("systemctl", "nft", "iptables", "ip6tables", "sysctl", "modprobe", "useradd", "groupadd", "userdel", "groupdel", "usermod",
         "apt", "apt-get", "add-apt-repository", "resolvectl", "dpkg", "dpkg-query", "systemd-run", "systemd-detect-virt", "ss", "ip",
         "curl", "swapon", "swapoff", "mkswap", "fallocate", "update-initramfs", "lsmod", "suricata", "suricata-update", "tetra",
         "dnscrypt-proxy", "logger", "chown", "chmod", "mv", "rm", "cp", "install", "ln", "mkdir", "tee", "umount", "mount")


def tree_hash(root):
    h = hashlib.sha256()
    for base, dirs, files in sorted(os.walk(root)):
        dirs.sort()
        h.update(base.encode())
        for name in sorted(files + [d for d in dirs if os.path.islink(os.path.join(base, d))]):
            p = os.path.join(base, name)
            h.update(p.encode())
            if os.path.islink(p):
                h.update(os.readlink(p).encode())
            else:
                with open(p, "rb") as f:
                    h.update(f.read())
                h.update(str(stat.S_IMODE(os.stat(p).st_mode)).encode())
    return h.hexdigest()


class RootCase(unittest.TestCase):
    """A test root that looks like a fresh Ubuntu 24.04 droplet with nginx, 4 GB and BTF."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="edr-inst-")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = os.path.join(self.base, "root")
        self.stubs = os.path.join(self.base, "stubs")
        self.log = os.path.join(self.base, "stub-calls.log")
        os.makedirs(self.root)
        os.makedirs(self.stubs)
        for name in STUBS:
            p = os.path.join(self.stubs, name)
            with open(p, "w") as f:
                f.write('#!/bin/sh\necho "%s $*" >> "%s"\nexit 0\n' % (name, self.log))
            os.chmod(p, 0o755)
        self.put("/etc/os-release", 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
        os.makedirs(self.root + "/run/systemd/system")
        self.put("/sys/kernel/btf/vmlinux", "")
        self.put("/proc/meminfo", "MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 1000000 kB\n")
        self.put("/usr/sbin/nginx", "#!/bin/sh\n", mode=0o755)
        self.put("/etc/nginx/nginx.conf", "http { }\n")
        self.probe("uname", "echo x86_64")

    def put(self, path, text="", mode=None):
        full = self.root + path
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)
        if mode is not None:
            os.chmod(full, mode)
        return full

    def probe(self, name, body, rc=0):
        self.put("/probe/" + name, "#!/bin/sh\n%s\nexit %d\n" % (body, rc), mode=0o755)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("EDR_", "SSH_"))}
        env["PATH"] = self.stubs + ":" + os.environ.get("PATH", "/usr/bin:/bin")
        env["EDR_AGENT_ROOT"] = self.root
        env.update(extra)
        return env

    def run_script(self, script, args, **extra):
        return subprocess.run(["bash", script] + list(args), capture_output=True, text=True, env=self.env(**extra), timeout=60,
                              stdin=subprocess.DEVNULL)

    def plan(self, *args, **extra):
        return self.run_script(INSTALL, ["--plan", "--from-checkout"] + list(args), **extra)

    def stub_calls(self):
        try:
            with open(self.log) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def manifest(self, doc, where="/var/lib/edr-install/manifest.json"):
        full = self.root + where
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            json.dump(doc, f)


def session(**kw):
    s = {"id": "1234abcd-0000-4000-8000-000000000000", "kind": "install", "started": 1, "finished": 2, "state": "confirmed",
         "from_version": None, "to_version": "0.1.0", "steps_done": [1, 2], "files": [], "dirs": [], "units": [], "sysctls": [],
         "packages": [], "ppa": None, "users": [], "conntrack_loaded_before": True, "policy_rc_d_ours": False, "swapfile": None,
         "notes": [], "not_rolled_back": []}
    s.update(kw)
    return s


def manifest_doc(*sessions):
    return {"v": 1, "version": "0.1.0", "phase": "P2",
            "components": {"web": True, "tetragon": False, "suricata": False, "kernel": False, "dns_lockdown": True, "sctp_block": True, "enrolled": False},
            "sessions": list(sessions)}


def extract_python(script_path):
    """The python programs embedded as <<'PY' here-documents, by their first words."""
    with open(script_path) as f:
        text = f.read()
    return re.findall(r"<<'PY'[^\n]*\n(.*?)\nPY\n", text, re.S)


def shell_functions(script_path, names):
    """The text of the named functions of a shell script. install.sh runs its argument parser and its steps at the top
    level, so it cannot be sourced whole: a test takes the functions it needs and runs them on their own. The end of a
    function is the first line, the opening one or a closing brace alone, after which bash accepts the text."""
    with open(script_path) as f:
        lines = f.read().split("\n")
    out = []
    for name in names:
        start = next((i for i, line in enumerate(lines) if line.startswith(name + "() {")), None)
        assert start is not None, "no function %s in %s" % (name, script_path)
        for end in range(start, len(lines)):
            if end > start and lines[end] != "}":
                continue
            text = "\n".join(lines[start:end + 1])
            if subprocess.run(["bash", "-n"], input=text, capture_output=True, text=True).returncode == 0:
                out.append(text)
                break
        else:
            raise AssertionError("function %s does not end" % name)
    return "\n".join(out) + "\n"


class FunctionCase(unittest.TestCase):
    """Functions of an installer run on their own, in a temporary directory. Every command that could change a system
    is a function here that writes its words to $CALLS and does nothing, so no test can touch the machine it runs on;
    a test redefines one of them where it needs another answer. $BASE is the temporary directory."""

    LOGGED = ("systemctl", "chown", "chgrp", "apt-get", "apt", "useradd", "groupadd", "userdel", "nft", "sysctl", "systemd-run",
              "modprobe", "dnscrypt-proxy", "resolvectl", "add-apt-repository")

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="edr-fn-")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.calls_path = os.path.join(self.base, "calls.log")

    def run_functions(self, script, names, body, **env):
        prelude = ["set -uo pipefail", 'BASE="%s"' % self.base, 'CALLS="%s"' % self.calls_path, ': > "$CALLS"',
                   'die() { echo "ERROR: $*" >&2; exit 2; }']
        prelude += ['%s() { echo "%s $*" >> "$CALLS"; }' % (n, n) for n in self.LOGGED]
        path = os.path.join(self.base, "harness.sh")
        with open(path, "w") as f:
            f.write("\n".join(prelude) + "\n" + shell_functions(script, names) + body + "\n")
        e = {k: v for k, v in os.environ.items() if not k.startswith(("EDR_", "SSH_"))}
        e.update(env)
        return subprocess.run(["bash", path], capture_output=True, text=True, env=e, timeout=60, stdin=subprocess.DEVNULL, cwd="/")

    def calls(self):
        try:
            with open(self.calls_path) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []


class TestCommon(unittest.TestCase):
    def test_scripts_exist(self):
        for p in (INSTALL, UNINSTALL):
            self.assertTrue(os.path.isfile(p) and os.access(p, os.X_OK), p)
