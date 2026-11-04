#!/usr/bin/env python3
"""Bounded tests for the isolated 2.0 Mac watchdog safety gates."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ai_relay_watchdog", ROOT / "scripts" / "ai-relay-watchdog.py")
WATCHDOG = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(WATCHDOG)


class WatchdogTests(unittest.TestCase):
    def run_main(self, remote):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = base / "state.json"
            log = base / "watchdog.log"

            def fake_ssh(host, remote_input, timeout=30):
                self.assertEqual(host, "server3-test")
                return subprocess.CompletedProcess(["ssh"], 0, json.dumps(remote) + "\n", "")

            original_ssh = WATCHDOG.ssh
            original_restart = WATCHDOG.restart
            restarts = []
            WATCHDOG.ssh = fake_ssh
            WATCHDOG.restart = lambda host: restarts.append(host)
            try:
                result = WATCHDOG.main_args_for_test("server3-test", state, log)
            finally:
                WATCHDOG.ssh = original_ssh
                WATCHDOG.restart = original_restart
            return result, json.loads(state.read_text()), log.read_text(), restarts

    def test_restart_requires_all_safety_gates(self):
        remote = {
            "service": "failed",
            "branch": "develop/2.0",
            "free_kb": 3 * 1024 * 1024,
            "writers": 0,
            "status": {"state": "stopped"},
        }
        result, record, log, restarts = self.run_main(remote)
        self.assertEqual(result, 0)
        self.assertEqual(restarts, ["server3-test"])
        self.assertEqual(record["action"], "restarted")
        self.assertIn('"action": "restarted"', log)

    def test_restart_is_suppressed_for_wrong_branch_or_active_writer(self):
        for change in ({"branch": "release/1.x"}, {"writers": 1}, {"free_kb": 1024}):
            remote = {
                "service": "failed",
                "branch": "develop/2.0",
                "free_kb": 3 * 1024 * 1024,
                "writers": 0,
                "status": {"state": "stopped"},
                **change,
            }
            result, record, _, restarts = self.run_main(remote)
            self.assertEqual(result, 0)
            self.assertEqual(restarts, [])
            self.assertEqual(record["action"], "restart_suppressed_by_safety_gate")


def _main_args_for_test(host, state, log):
    """Invoke main without reparsing this process's command line."""
    import argparse
    original = WATCHDOG.argparse.ArgumentParser.parse_args
    WATCHDOG.argparse.ArgumentParser.parse_args = lambda self: argparse.Namespace(
        host=host, state=state, log=log
    )
    try:
        return WATCHDOG.main()
    finally:
        WATCHDOG.argparse.ArgumentParser.parse_args = original


WATCHDOG.main_args_for_test = _main_args_for_test


if __name__ == "__main__":
    unittest.main()
