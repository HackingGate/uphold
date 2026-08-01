"""The MSRV is written twice, so something has to hold the two copies together.

`rust-version` in Cargo.toml is what cargo enforces at resolve time. `want` on
the rustc row in toolchain.toml is what the host preflight enforces before a
build starts, and cargo cannot read it -- the manifest formats are not the same
file and neither tool knows about the other. Two copies of one number is what
`single-authoritative-source` refuses, and the reason it is refused is on
display here: the drift that matters is the silent direction, where
toolchain.toml keeps waving through a compiler the crate no longer builds on.

So the copy is allowed and the drift is not. This is the check that makes the
difference.
"""

from __future__ import annotations

import shutil
import subprocess
import tomllib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _rustc_row() -> dict:
    manifest = tomllib.loads((REPO / "toolchain.toml").read_text(encoding="utf-8"))
    for tool in manifest.get("tool", []):
        if tool.get("name") == "rustc":
            return tool
    raise AssertionError("toolchain.toml declares no rustc tool")


class MsrvAgreement(unittest.TestCase):
    def test_the_two_manifests_name_the_same_msrv(self) -> None:
        cargo = tomllib.loads((REPO / "Cargo.toml").read_text(encoding="utf-8"))
        msrv = cargo["package"].get("rust-version")
        self.assertIsNotNone(msrv, "Cargo.toml declares no rust-version")

        self.assertEqual(
            _rustc_row().get("want"),
            f">={msrv}",
            "toolchain.toml's rustc `want` and Cargo.toml's rust-version have "
            "drifted; bump both in the commit that raises the MSRV",
        )


@unittest.skipUnless(shutil.which("rustc"), "no rustc on this host")
class Preflight(unittest.TestCase):
    """The version comparison is a gate only if it can refuse.

    `check` reports on the HOST, so what it says is not a property of this tree
    -- the catalog job has no Rust toolchain at all and is right to fail it.
    What IS a property of the tree is whether the rustc row's constraint is
    wired to anything, and the only way to see that is to state one the host
    cannot meet: every box a developer builds on is above the real floor, so a
    comparison that was never wired would pass on all of them.

    Skipped where there is no rustc, because then the run below refuses for the
    reason "not installed" and would pass while proving nothing.
    """

    def _check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["./scripts/deps.sh", "check"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_version_the_host_cannot_satisfy_is_refused(self) -> None:
        manifest = (REPO / "toolchain.toml").read_text(encoding="utf-8")
        want = _rustc_row()["want"]
        impossible = manifest.replace(f'want = "{want}"', 'want = ">=999.0"', 1)
        self.assertNotEqual(manifest, impossible, "the rustc `want` line moved")

        original = (REPO / "toolchain.toml").read_bytes()
        try:
            (REPO / "toolchain.toml").write_text(impossible, encoding="utf-8")
            done = self._check()
        finally:
            (REPO / "toolchain.toml").write_bytes(original)

        report = done.stdout + done.stderr
        self.assertNotEqual(done.returncode, 0, report)
        # The exit code alone would also be earned by a missing rustc, an
        # unreadable manifest, or a failed setup step -- three ways to pass this
        # test without the constraint ever being compared.
        self.assertIn("999.0", report)


if __name__ == "__main__":
    unittest.main()
