"""Shared helpers for the agent's tests: the import path, a temporary root, and small fakes.

This file has no tests of its own. The fakes for the ban engine, the uplink and the hub commands are
installed into sys.modules only when the real modules (written by another agent) cannot be imported.
"""
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.normpath(os.path.join(HERE, "..", "agent"))
if CODE not in sys.path:
    sys.path.insert(0, CODE)

from edragent import config as cfgmod            # noqa: E402
from edragent import event as evmod              # noqa: E402
from edragent import ids                         # noqa: E402
from edragent.paths import Paths                 # noqa: E402


class FakeBanEngine:
    """Stands in for edragent.bans.BanEngine."""

    def __init__(self, cfg=None, paths=None):
        self.observed = []
        self.to_return = []
        self.ticks = 0

    def observe(self, event, now):
        self.observed.append(event)
        out, self.to_return = self.to_return, []
        return out

    def tick(self, now):
        self.ticks += 1
        return []

    def set_policy(self, doc):
        pass

    def counts(self):
        return {}

    def last_apply_error(self):
        return ""


class FakeUplink:
    """Stands in for edragent.uplink.Uplink: local mode, remembers what it was given."""

    def __init__(self, cfg=None, paths=None, ban_engine=None, heartbeat_fn=None, **kw):
        self.submitted = []
        self.heartbeat_fn = heartbeat_fn
        self.started = False
        self.stopped = None
        self.local_event_cb = None
        self.mode = "local"

    def start(self):
        self.started = True

    def submit(self, event):
        self.submitted.append(event)

    def enrolled(self):
        return self.mode == "enrolled"

    def status(self):
        return {"mode": self.mode, "hub": None, "host_uuid": None, "last_heartbeat_ok": None, "last_error": "",
                "last_code": None, "spool": {"depth": 0, "bytes": 0, "dropped": {"hi": 0, "lo": 0}}}

    def stop(self, shutdown=False):
        self.stopped = shutdown


def install_fakes_if_missing():
    """Fake edragent.bans, .uplink and .hubcmds in sys.modules, only for those whose real import fails."""
    import importlib
    for name, attrs in (("bans", {"BanEngine": FakeBanEngine}), ("uplink", {"Uplink": FakeUplink}),
                        ("hubcmds", {"register": lambda sub: None})):
        full = "edragent." + name
        try:
            importlib.import_module(full)
        except ImportError:
            mod = types.ModuleType(full)
            for k, v in attrs.items():
                setattr(mod, k, v)
            sys.modules[full] = mod


install_fakes_if_missing()


class Tmp(unittest.TestCase):
    """A test case with a temporary EDR_AGENT_ROOT and a Paths for it."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="edr-agent-test-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.paths = Paths(root=self.root)
        os.makedirs(self.paths.state_dir, mode=0o700, exist_ok=True)
        os.makedirs(self.paths.run_dir, exist_ok=True)
        os.makedirs(self.paths.etc_dir, exist_ok=True)
        self.clock = Clock()
        evmod.configure(cfgmod.defaults(), boot_id="b" * 36)
        ids.init(self.paths)

    def write(self, path, text, mode=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def append(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(text)

    def conf(self, text):
        self.write(self.paths.local_conf, text)
        return cfgmod.load(self.paths)


class Clock:
    def __init__(self, start=1_795_000_000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, secs):
        self.t += secs
        return self.t


def hub_modules():
    """(hub_common, hub_ingest) from the hub's directory, or None when they cannot be imported."""
    hub = os.path.normpath(os.path.join(HERE, "..", "..", "server_hub", "hub"))
    if hub not in sys.path:
        sys.path.append(hub)
    try:
        import hub_common
        import hub_ingest
        return hub_common, hub_ingest
    except Exception:           # the hub is another agent's work; its absence must not fail these tests
        return None
