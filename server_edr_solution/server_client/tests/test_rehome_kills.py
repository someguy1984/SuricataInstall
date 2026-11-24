"""A rehome killed (SIGKILL) at the boundaries that tests/restore_drill_local.py cannot stop at from outside (PLAN 5).

Each step does its work and then saves its number in rehome.json, so a kill between the two leaves the file one step
behind the disk. `rehome --rollback` (what the timer of step 3 runs) must still leave the agent with exactly one
working identity, never with none. The loopback run stops the real process only where it waits: in step 2 (a held
connection), in step 6 and in step 7 (the deregister). KilledBeforeEveryWrite covers the rest: it takes a copy of the
whole agent root before every write, link flip, deletion and call to the hub of a real rehome, then plays the two
things that can follow a kill on each copy: `rehome --rollback` (the timer of step 3, the operator) and the start of
edr-agent (`rehome-resume`, PLAN 5 row 7). TestStartAfterAKill has one named case per row of the rollback table."""

import json
import os
import shutil
import unittest
from unittest import mock

import test_identity as TI
from edragent import identity as idn
from edragent import spool as sp


def state_path(p):
    return os.path.join(str(p.identity_dir), "rehome.json")


class StagedKill(TI.RehomeCase):
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


class KilledBetweenWorkAndSave(StagedKill):
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


def tree(root):
    """Everything under root as {relative path: ('d',) | ('l', target) | ('f', bytes)}, to compare two states of the disk."""
    out = {}
    for base, dirs, files in os.walk(root):
        for n in dirs + files:
            full = os.path.join(base, n)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                out[rel] = ("l", os.readlink(full))
            elif os.path.isdir(full):
                out[rel] = ("d",)
            else:
                with open(full, "rb") as f:
                    out[rel] = ("f", f.read())
    return out


def restore(root, snap):
    for n in os.listdir(root):
        full = os.path.join(root, n)
        if os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full)
        else:
            os.unlink(full)
    shutil.copytree(snap, root, symlinks=True, dirs_exist_ok=True)


class KilledBeforeEveryWrite(TI.RehomeCase):
    """A real rehome, copied to disk before each step that changes anything. Each copy is what a SIGKILL at that
    point leaves behind (the call itself has not started), and the last copy is the finished move."""

    NEW_ADDRS = ["127.0.0.1"]

    def snapshots(self, **kw):
        snaps, root = [], self.env.root
        tmp = os.path.join(os.path.dirname(root), os.path.basename(root) + "-snaps")
        os.makedirs(tmp)
        self.addCleanup(shutil.rmtree, tmp, True)
        busy = []
        names = ("rehome.json", "rehome-dropin.saved")
        real = {"atomic_write": idn.atomic_write, "flip_current": idn.flip_current, "deregister": idn.deregister,
                "rmtree": shutil.rmtree, "unlink": os.unlink}
        ops = idn.SystemOps(self.p)                     # a copy of self.ops that copies the disk; the recovery uses self.ops

        def snap(label):
            if busy:                                    # a write made by a write we already copied before
                return
            if len(snaps) > 100:
                raise AssertionError("more than 100 copies: a loop")
            busy.append(1)
            try:
                st = idn.load_rehome_state(self.p) if idn.rehome_in_progress(self.p) else None
                d = os.path.join(tmp, "%02d" % len(snaps))
                shutil.copytree(root, d, symlinks=True)
                snaps.append((label if st is None else "%s [state step %s]" % (label, st["step"]), d))
            finally:
                busy.pop()

        def wrap(name, label):
            fn = real[name]

            def inner(*a, **kw):
                snap(label(*a) if callable(label) else label)
                busy.append(1)
                try:
                    return fn(*a, **kw)
                finally:
                    busy.pop()
            return inner

        def unlink(path, *a, **kw):
            if os.path.basename(str(path)) in names:
                snap("unlink " + os.path.basename(str(path)))
            return real["unlink"](path, *a, **kw)

        def rmtree(path, *a, **kw):
            snap("rmtree " + os.path.basename(str(path)))
            return real["rmtree"](path, *a, **kw)

        def op(name):
            fn = getattr(ops, name)

            def inner(*a, **kw):
                snap("ops." + name)
                return fn(*a, **kw)
            setattr(ops, name, inner)

        for n in ("arm_rollback_timer", "daemon_reload", "restart_agent", "disarm_rollback_timer"):
            op(n)
        with mock.patch.object(idn, "atomic_write", wrap("atomic_write", lambda p, *a: "write " + os.path.basename(str(p)))), \
                mock.patch.object(idn, "flip_current", wrap("flip_current", lambda *a: "flip current")), \
                mock.patch.object(idn, "deregister", wrap("deregister", "deregister")), \
                mock.patch.object(shutil, "rmtree", rmtree), mock.patch.object(os, "unlink", unlink):
            rc = self.rehome(ops=ops, **kw)
        self.assertEqual(rc, 0, self.logs)
        snaps.append(("finished", self.copy_now(tmp)))
        return snaps

    def copy_now(self, tmp):
        d = os.path.join(tmp, "zz-final")
        shutil.copytree(self.env.root, d, symlinks=True)
        return d

    def setUp(self):
        super().setUp()
        idn.write_trusted(self.p, ["127.0.0.1"])                  # root's record, as an enrollment leaves it
        self.orig_dropin = TI.slurp(self.ops.dropin_path)

    def test_the_run_is_cut_at_every_step_of_the_plan(self):
        snaps = self.snapshots()
        labels = [l for l, _ in snaps]
        self.assertGreaterEqual(len(snaps), 20, labels)
        for step in range(2, 8):                         # a copy exists with the state file at each of steps 2 to 7
            self.assertTrue(any("[state step %d]" % step in l for l in labels), (step, labels))
        for need in ("flip current", "ops.daemon_reload", "ops.restart_agent", "ops.disarm_rollback_timer", "deregister",
                     "write rehome-dropin.saved", "write 10-hub.conf", "unlink rehome-dropin.saved", "unlink rehome.json"):
            self.assertTrue(any(l.startswith(need) for l in labels), (need, labels))

    def test_rollback_after_a_kill_at_any_point_leaves_one_working_identity(self):
        for label, d in self.snapshots():
            with self.subTest(killed_before=label):
                restore(self.env.root, d)
                st = idn.load_rehome_state(self.p)
                self.ops.calls.clear()
                rc = idn.rollback(self.p, self.ops, log=self.logs.append)
                ident = idn.load_current(self.p)
                self.assertIsNotNone(ident)                                       # never a link to nothing
                self.assertFalse(idn.rehome_in_progress(self.p))
                self.assertEqual(idn.read_host_id(self.p), ident.host_uuid)       # the host-id belongs to the identity in use
                self.assertEqual(idn.read_trusted(self.p)["addresses"], idn.dropin_addresses(self.dropin()))
                self.assertNotIn("rehome", idn.read_trusted(self.p)) if st is not None else None
                if st is not None and st["step"] >= 7 or label == "finished" or label.startswith("unlink rehome.json"):
                    self.assertEqual((rc, idn.current_gen_name(self.p), idn.gen_numbers(self.p)), (0, "gen-2", [2]), label)
                    self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)
                elif st is not None:
                    self.assertEqual((rc, idn.current_gen_name(self.p), idn.gen_numbers(self.p)), (4, "gen-1", [1]), label)
                    self.assertEqual(self.dropin(), self.orig_dropin)
                    self.assertEqual(idn.read_host_id(self.p), self.old.uuid)
                else:                                                             # killed in step 2, or before the state file: nothing to undo
                    self.assertEqual((rc, idn.current_gen_name(self.p)), (0, "gen-1"), label)
                    self.assertEqual(self.dropin(), self.orig_dropin)
                self.assertEqual(idn.rollback(self.p, self.ops), 0)               # and a second run changes nothing

    def test_the_flag_of_drop_spool_does_not_survive_a_rollback(self):
        snaps = self.snapshots(drop_spool=True)
        flag = os.path.join(str(self.p.identity_dir), "drop-spool.flag")
        self.assertTrue(any(l.startswith("write drop-spool.flag") for l, _ in snaps))
        for label, d in snaps:
            with self.subTest(killed_before=label):
                restore(self.env.root, d)
                st = idn.load_rehome_state(self.p)
                idn.rollback(self.p, self.ops)
                if st is not None and st["step"] < 7:
                    self.assertFalse(os.path.exists(flag), label)

    def test_a_start_after_a_kill_finishes_step_7_and_touches_nothing_before_it(self):
        for label, d in self.snapshots():
            with self.subTest(killed_before=label):
                restore(self.env.root, d)
                st = idn.load_rehome_state(self.p)
                before = tree(self.env.root)
                self.ops.calls.clear()
                res = idn.resume(self.p, self.ops, log=self.logs.append)
                if st is not None and st["step"] >= 7:
                    self.assertEqual(res, "finished", label)
                    self.assertEqual((idn.current_gen_name(self.p), idn.gen_numbers(self.p)), ("gen-2", [2]))
                    self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)
                    self.assertEqual(idn.read_trusted(self.p), {"addresses": self.NEW_ADDRS})
                    self.assertEqual(idn.dropin_addresses(self.dropin()), self.NEW_ADDRS)
                    self.assertFalse(idn.rehome_in_progress(self.p))
                    self.assertFalse(os.path.exists(os.path.join(str(self.p.identity_dir), "rehome-dropin.saved")))
                    self.assertIsNotNone(idn.load_current(self.p))
                else:                                                             # the plan gives these to the timer and the operator
                    self.assertEqual(res, "none" if st is None and not idn.rehome_in_progress(self.p) else "pending", label)
                    self.assertEqual(tree(self.env.root), before, label)
                    self.assertEqual(self.ops.calls, [], label)
                self.assertEqual(idn.resume(self.p, self.ops), "none" if not idn.rehome_in_progress(self.p) else "pending")


class TestStartAfterAKill(StagedKill):
    """One case per row of the rollback table in PLAN 5, for what the next start of edr-agent does."""

    def untouched(self, step, **kw):
        saved = self.stage(step, **kw)
        before = tree(self.env.root)
        self.ops.calls.clear()
        self.assertEqual(idn.resume(self.p, self.ops, log=self.logs.append), "pending")
        self.assertEqual(tree(self.env.root), before)
        self.assertEqual(self.ops.calls, [])
        self.assertTrue(any("waiting at step %d" % step in l for l in self.logs), self.logs)
        return saved

    def test_rows_1_and_2_have_no_state_file_and_a_start_does_nothing(self):
        n, csr = idn.new_generation(self.p, self.ops)                                  # the staged generation of a kill in steps 1 to 2
        self.ops.calls.clear()
        before = tree(self.env.root)
        self.assertEqual(idn.resume(self.p, self.ops, log=self.logs.append), "none")
        self.assertEqual(tree(self.env.root), before)
        self.assertEqual(self.ops.calls, [])

    def test_rows_3_and_4_a_start_leaves_the_timer_to_undo_the_move(self):
        self.untouched(2)
        self.untouched(3)
        self.untouched(3, dropin=True)                                                  # the both-hubs drop-in is on disk, step 4 not yet saved
        self.untouched(4)
        self.assertEqual(idn.rollback(self.p, self.ops), 4)                             # and the timer still can

    def test_rows_5_and_6_a_start_leaves_a_flipped_move_to_the_timer(self):
        self.untouched(4, flipped=True, dropin=True)
        self.untouched(5, flipped=True, dropin=True)
        self.untouched(6, flipped=True, dropin=True)
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.rollback(self.p, self.ops), 4)                             # the timer returns to the old hub
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_a_state_file_nobody_can_read_is_left_alone(self):
        sp.atomic_write(state_path(self.p), "not json", 0o600)
        self.assertEqual(idn.resume(self.p, self.ops, log=self.logs.append), "pending")
        self.assertTrue(os.path.exists(state_path(self.p)))
        self.assertEqual(self.ops.calls, [])

    def kill_in_step_7(self):
        """A real rehome whose step 7 dies at the deregister: the state file says 7 and the old generation is still there."""
        def boom(*a, **kw):
            raise SystemExit("killed")
        real = idn.deregister
        idn.deregister = boom
        try:
            with self.assertRaises(SystemExit):
                self.rehome()
        finally:
            idn.deregister = real
        self.assertEqual(idn.load_rehome_state(self.p)["step"], 7)

    def test_row_7_a_start_finishes_the_cleanup_once(self):
        self.kill_in_step_7()
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])
        self.assertIn("IPAddressAllow=127.0.0.1", self.dropin())
        self.ops.calls.clear()
        self.assertEqual(idn.resume(self.p, self.ops, log=self.logs.append), "finished")
        self.assertEqual((idn.current_gen_name(self.p), idn.gen_numbers(self.p)), ("gen-2", [2]))
        self.assertEqual(self.old.deregistered, [(self.old.uuid, {"reason": "rehome"})])          # the old hub was told
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)
        self.assertFalse(idn.rehome_in_progress(self.p))
        self.assertEqual(idn.read_trusted(self.p), {"addresses": ["127.0.0.1"]})
        self.assertTrue(any(c[:2] == ["systemctl", "daemon-reload"] for c in self.ops.calls))
        self.assertEqual(idn.cleanup_generations(self.p), [])                                      # renewal and cleanup run again
        self.ops.calls.clear()
        self.assertEqual(idn.resume(self.p, self.ops), "none")                                     # a second start does nothing
        self.assertEqual(self.ops.calls, [])
        self.assertEqual(len(self.old.deregistered), 1)

    def test_a_start_does_not_tell_the_old_hub_twice(self):
        self.kill_in_step_7()
        st = idn.load_rehome_state(self.p)
        st["deregistered"] = True
        sp.atomic_write(state_path(self.p), json.dumps(st), 0o600)
        self.assertEqual(idn.resume(self.p, self.ops), "finished")
        self.assertEqual(self.old.deregistered, [])

    def test_a_state_file_the_agent_rewrote_cannot_choose_the_drop_in(self):
        self.kill_in_step_7()
        idn.write_trusted(self.p, ["127.0.0.1"])                                                   # root's record as a kill after its commit leaves it
        st = idn.load_rehome_state(self.p)
        st.update(new_addresses=["198.51.100.66"], old_addresses=["198.51.100.67"])
        sp.atomic_write(state_path(self.p), json.dumps(st), 0o600)
        self.assertEqual(idn.resume(self.p, self.ops), "finished")
        self.assertEqual(idn.dropin_addresses(self.dropin()), ["127.0.0.1"])
        self.assertEqual(idn.read_trusted(self.p), {"addresses": ["127.0.0.1"]})

    def test_a_start_does_not_act_on_a_state_file_that_does_not_match_the_identity(self):
        self.kill_in_step_7()
        idn.flip_current(self.p, "gen-1")
        before = tree(self.env.root)
        self.assertEqual(idn.resume(self.p, self.ops, log=self.logs.append), "failed")
        self.assertEqual(tree(self.env.root), before)

    def test_without_root_s_own_record_nothing_is_written_to_the_drop_in(self):
        self.kill_in_step_7()
        os.unlink(idn.trusted_path(self.p))
        before = self.dropin()
        self.assertEqual(idn.resume(self.p, self.ops), "failed")
        self.assertEqual(self.dropin(), before)
        self.assertTrue(idn.rehome_in_progress(self.p))                                            # nothing was deleted either


if __name__ == "__main__":
    unittest.main()
