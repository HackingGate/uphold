"""Exercise the shipped launchers, including failure before uphold can answer."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CodexPlugin(unittest.TestCase):
    def setUp(self):
        marketplace = json.loads(
            (ROOT / ".agents/plugins/marketplace.json").read_text()
        )
        entry = marketplace["plugins"][0]
        plugin = ROOT / entry["source"]["path"]
        manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
        self.assertEqual(manifest["name"], entry["name"])
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text())
        key = f"{entry['name']}@{marketplace['name']}"
        self.assertTrue(config["plugins"][key]["enabled"])
        self.hooks = json.loads((plugin / manifest["hooks"]).read_text())["hooks"]

    def test_lifecycle_and_mcp_coverage(self):
        self.assertEqual(set(self.hooks), {"PreToolUse", "SessionStart", "Stop"})
        self.assertEqual(self.hooks["PreToolUse"][0]["matcher"], "mcp__.*")
        self.assertTrue(self.hooks["SessionStart"][0]["hooks"][0]["async"])
        self.assertEqual(self.hooks["Stop"][0]["hooks"][0]["timeout"], 900)

    def test_launchers_preserve_the_protocol_and_block_execution_failures(self):
        with tempfile.TemporaryDirectory(prefix="uphold-codex-") as directory:
            binary = Path(directory) / "uphold"
            for event, groups in self.hooks.items():
                for group in groups:
                    for handler in group["hooks"]:
                        self.assertEqual(handler["type"], "command")
                        command = handler["command"]
                        for status in (0, 1, 2, 127, None):
                            with self.subTest(event=event, status=status):
                                if status is None:
                                    binary.unlink()
                                else:
                                    binary.write_text(
                                        "#!/bin/sh\n"
                                        '[ "$1" = hook ] && [ "$2" = codex ] '
                                        '&& [ "$#" = 2 ] || exit 99\n'
                                        "IFS= read -r event\n"
                                        'printf "%s\\n" "$event"\n'
                                        f"exit {status}\n"
                                    )
                                    binary.chmod(0o755)
                                payload = json.dumps({"hook_event_name": event})
                                result = subprocess.run(
                                    ["/bin/sh", "-c", command],
                                    input=payload + "\n",
                                    text=True,
                                    capture_output=True,
                                    env={**os.environ, "PATH": directory},
                                    check=False,
                                )
                                self.assertEqual(
                                    result.returncode, 0 if status == 0 else 2
                                )
                                if status is not None:
                                    self.assertEqual(result.stdout, payload + "\n")
                                if status != 0:
                                    self.assertIn(
                                        "uphold hook codex failed", result.stderr
                                    )
