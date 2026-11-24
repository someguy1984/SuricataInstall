"""A rehome killed (SIGKILL) at the boundaries that tests/restore_drill_local.py cannot stop at from outside (PLAN 5).

Each step does its work and then saves its number in rehome.json, so a kill between the two leaves the file one step
behind the disk. `rehome --rollback` (what the timer of step 3 runs) must still leave the agent with exactly one
working identity, never with none. The loopback run stops the real process only where it waits: in step 2 (a held
connection), in step 6 and in step 7 (the deregister)."""

import json
import os
import shutil
import unittest

import test_identity as TI
from edragent import identity as idn
from edragent import spool as sp


def state_path(p):
    return os.path.join(str(p.identity_dir), "rehome.json")


class KilledBetweenWorkAndSave(TI.RehomeCase):
    def stage(self, step, flipped=False, dropin=False):
        """What a kill leaves: gen-2 staged, rehome.json at `step`, and the work of the next step already on disk."""
        n, csr = idn.new_generation(self.p, self.ops)
        d = idn.gen_path(self.p, n)
        idn.write_hub_conf(os.path.join(d, "hub.conf"), ["127.0.0.1"], 9999, 8444, "22222222-2222-4222-8222-222222222222", "0" * 64)
        saved = TI.slurp(self.ops.dropin_path)
        st = {"v": 1, "step": step, "prev": "gen-1", "new": "gen-2", "old_addresses": ["127.0.0.1"], "new_addresses": ["192.0.2.9"],
              "new_host_uuid": "22222222-2222-4222-8222-222222222222", "old_host_uuid": self.old.uuid, "had_dropin": True,
              "armed_at": 1, "droplet_id": "424242"}
        idn.write_trusted(self.p, ["127.0.0.1"], {"old": ["127.0.0.1"], "new": ["192.0.2.9"]})
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome-dropin.saved"), saved, 0o600)
        sp.atomic_write(state_path(self.p), json.dumps(st), 0o600)
        if dropin:
            self.ops.write_dropin(["127.0.0.1", "192.0.2.9"])
        if flipped:
            idn.flip_current(self.p, "gen-2")
        self.ops.calls.clear()
        return saved

    def test_killed_after_the_flip_before_step_5_is_saved_current_goes_back(self):
        saved = self.stage(4, flipped=True, dropin=True)
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.rollback(self.p, self.ops, log=self.logs.append), 4)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")                     # never a link to a generation that was deleted
        self.assertIsNotNone(idn.load_current(self.p))
        self.assertEqual(idn.gen_numbers(self.p), [1])
        self.assertEqual(self.dropin(), saved)
        self.assertTrue(any(c[:2] == ["systemctl", "restart"] for c in self.ops.calls))   # the agent had been told to use gen-2
        self.assertFalse(os.path.exists(state_path(self.p)))

    def test_killed_after_the_drop_in_was_written_before_step_4_is_saved_the_drop_in_goes_back(self):
        saved = self.stage(3, dropin=True)
        self.assertIn("192.0.2.9", self.dropin())
        self.assertEqual(idn.rollback(self.p, self.ops, log=self.logs.append), 4)
        self.assertEqual(self.dropin(), saved)
        self.assertEqual(idn.read_trusted(self.p), {"addresses": ["127.0.0.1"]})
        self.assertTrue(any(c[:2] == ["systemctl", "daemon-reload"] for c in self.ops.calls))
        self.assertFalse(any(c[:2] == ["systemctl", "restart"] for c in self.ops.calls))   # current never moved
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_killed_with_nothing_done_beyond_the_saved_state_touches_nothing_else(self):
        for step in (2, 3):
            with self.subTest(step=step):
                shutil.rmtree(str(self.p.identity_dir), ignore_errors=True)
                TI.support.make_identity(self.env, self.old.pki, self.old.fleet_port, cn=self.old.uuid)
                self.ops.write_dropin(["127.0.0.1"])
                saved = self.stage(step)
                self.assertEqual(idn.rollback(self.p, self.ops, log=self.logs.append), 4)
                self.assertEqual(idn.current_gen_name(self.p), "gen-1")
                self.assertEqual(self.dropin(), saved)
                self.assertEqual(idn.gen_numbers(self.p), [1])
                self.assertFalse(any(c[:2] in (["systemctl", "daemon-reload"], ["systemctl", "restart"]) for c in self.ops.calls))
                self.assertEqual(idn.rollback(self.p, self.ops), 0)


class KilledInStepTwo(TI.RehomeCase):
    def test_a_staged_generation_left_by_a_kill_does_not_stop_the_next_rehome(self):
        n, csr = idn.new_generation(self.p, self.ops)                                  # what a kill in step 2 leaves: key and CSR, no state file
        self.assertEqual(n, 2)
        self.assertFalse(idn.rehome_in_progress(self.p))
        self.assertEqual(idn.rollback(self.p, self.ops), 0)                            # nothing to undo
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        self.assertEqual(self.rehome(), 0, self.logs)
        self.assertEqual(idn.current_gen_name(self.p), "gen-3")                        # numbering skipped the stray one
        self.assertEqual(idn.cleanup_generations(self.p), [2])                         # and the first heartbeat on gen-3 removes it
        self.assertEqual(idn.gen_numbers(self.p), [3])


if __name__ == "__main__":
    unittest.main()
