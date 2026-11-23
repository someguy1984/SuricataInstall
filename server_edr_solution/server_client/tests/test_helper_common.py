"""Shared bits for the root-helper tests: load an extension-less helper as a module,
run it as `python3 -I`, and make temporary roots. Standard library only, no root needed."""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True        # the helpers have no .py name: keep their bytecode out of agent/
HERE = os.path.dirname(os.path.realpath(__file__))
CLIENT = os.path.dirname(HERE)
AGENT = os.path.join(CLIENT, "agent")
FILES = os.path.join(CLIENT, "files")
TETRAGON = os.path.join(CLIENT, "tetragon")
COMMON = os.path.join(os.path.dirname(CLIENT), "common")


def load_helper(name):
    """Import agent/<name> (no .py) as a module. Keeps one copy per name."""
    key = "helper_" + name.replace("-", "_")
    if key in sys.modules:
        return sys.modules[key]
    path = os.path.join(AGENT, name)
    loader = importlib.machinery.SourceFileLoader(key, path)
    spec = importlib.util.spec_from_loader(key, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    loader.exec_module(mod)
    return mod


def run_helper(name, args, timeout=30, env=None, cwd=None):
    """Run a helper as `python3 -I` and return (rc, stdout, stderr)."""
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C"}
    if env:
        e.update(env)
    r = subprocess.run([sys.executable, "-I", os.path.join(AGENT, name)] + list(args), capture_output=True, text=True,
                       timeout=timeout, env=e, cwd=cwd or tempfile.gettempdir())
    return r.returncode, r.stdout, r.stderr


def have(tool):
    return shutil.which(tool) is not None


class TmpCase(unittest.TestCase):
    """A test case with a temporary --root directory per test."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="edr-test-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def put(self, path, text="", mode=None, binary=False):
        full = self.root + path
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb" if binary else "w") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(full, mode)
        return full

    def read_json(self, path):
        with open(self.root + path, encoding="utf-8") as fh:
            return json.load(fh)


class TestCommon(unittest.TestCase):
    def test_helpers_exist_and_compile(self):
        for name in ("edr-bans", "edr-inventory", "edr-policy-check", "edr-diskguard", "edr-dns-watch",
                     "edr-home-net", "edr-droplet-id", "edr-notify"):
            path = os.path.join(AGENT, name)
            self.assertTrue(os.path.isfile(path), name)
            with open(path, encoding="utf-8") as fh:
                compile(fh.read(), name, "exec")
            self.assertTrue(os.access(path, os.X_OK), name + " is not executable")


if __name__ == "__main__":
    unittest.main()
