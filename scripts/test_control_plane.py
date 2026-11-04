#!/usr/bin/env python3
"""Bounded regression tests for the isolated 2.0 control-plane scripts."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "scripts" / "development-worker.py"


class ControlPlaneTests(unittest.TestCase):
    def wait_for(self, path, predicate, process, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                try:
                    value = json.loads(path.read_text())
                    if predicate(value):
                        return value
                except (OSError, json.JSONDecodeError):
                    # Readers must tolerate an update in progress; atomic replace
                    # means they should never observe a partial committed file.
                    pass
            if process.poll() is not None:
                break
            time.sleep(0.02)
        self.fail(f"timed out waiting for {path}")

    def worker(self, state, public, codex, minimum="0"):
        repo = state.parent / "repo"
        if not repo.exists():
            subprocess.run(["git", "init", "-q", "-b", "develop/2.0", str(repo)], check=True)
        return subprocess.Popen(
            [sys.executable, str(WORKER), "--repo", str(repo), "--codex", str(codex),
             "--state", str(state), "--public-status", str(public),
             "--expected-branch", "develop/2.0", "--min-free-gb", minimum],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=state.parent,
        )

    def test_status_is_atomic_and_worker_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = base / "state"
            public = base / "public.json"
            codex = base / "codex"
            codex.write_text("#!/bin/sh\nexit 0\n")
            codex.chmod(0o700)
            first = self.worker(state, public, codex)
            try:
                self.wait_for(state / "status.json", lambda v: v.get("state") in ("running", "waiting"), first)
                second = self.worker(state, public, codex)
                _, second_err = second.communicate(timeout=2)
                self.assertEqual(second.returncode, 75, second_err)
                self.assertIn(json.loads(public.read_text())["state"], ("running", "waiting"))
            finally:
                first.send_signal(signal.SIGTERM)
                first.communicate(timeout=3)

    def test_wrong_branch_gate_does_not_run_codex(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = base / "state"
            repo = base / "repo"
            subprocess.run(["git", "init", "-q", "-b", "develop/2.0", str(repo)], check=True)
            public = base / "public.json"
            marker = base / "ran"
            codex = base / "codex"
            codex.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
            codex.chmod(0o700)
            process = subprocess.run(
                [sys.executable, str(WORKER), "--repo", str(repo), "--codex", str(codex),
                 "--state", str(state), "--public-status", str(public),
                 "--expected-branch", "not-this-branch", "--min-free-gb", "0"],
                capture_output=True, text=True, timeout=3, cwd=base,
            )
            self.assertEqual(process.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(public.read_text())["state"], "wrong_branch")


if __name__ == "__main__":
    unittest.main()
