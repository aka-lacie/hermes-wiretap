"""Real-browser layout geometry (test_layout.mjs): column ends reachable, panes stable across async loads, Calls rows
keep their place when expanded. Needs Node + Playwright with a Chromium build; skipped explicitly otherwise.

    WIRETAP_PLAYWRIGHT_DIR=<dir containing node_modules/playwright>  [WIRETAP_CHROMIUM=<chrome executable>]
"""
import os
import shutil
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


class LayoutBrowserTest(unittest.TestCase):
    def test_layout_geometry_in_chromium(self):
        pw = os.environ.get("WIRETAP_PLAYWRIGHT_DIR", "")
        if not shutil.which("node") or not pw or not (Path(pw) / "node_modules" / "playwright").is_dir():
            self.skipTest("set WIRETAP_PLAYWRIGHT_DIR to a directory with node_modules/playwright (and a Chromium build)")
        cmd = ["node", str(HERE / "tests" / "test_layout.mjs"), str(HERE / "dashboard/dist/index.js"), str(HERE / "dashboard/dist/style.css"), pw]
        if os.environ.get("WIRETAP_CHROMIUM"):
            cmd.append(os.environ["WIRETAP_CHROMIUM"])
        env = dict(os.environ)
        # Chromium's singleton socket lives under TMPDIR and fails on long paths (sun_path is ~107 bytes)
        if len(env.get("TMPDIR", "/tmp")) > 60:
            short = env.get("XDG_RUNTIME_DIR", "")
            if not short or not os.path.isdir(short) or len(short) > 60:
                self.skipTest("TMPDIR is too long for Chromium's socket and no short XDG_RUNTIME_DIR is available")
            env["TMPDIR"] = short
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
        if r.returncode and "Executable doesn't exist" in r.stderr + r.stdout:
            self.skipTest("Playwright has no Chromium build; set WIRETAP_CHROMIUM")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
