"""The skills uphold tracks carry the frontmatter the Agent Skills spec requires.

https://agentskills.io/specification: a skill is a directory holding SKILL.md,
whose YAML frontmatter has `name` (1-64 characters, lowercase letters, digits
and single hyphens, not opening or closing with one, matching the directory)
and `description` (1-1024 characters, non-empty).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def frontmatter(text: str) -> dict[str, str]:
    """The top-level `key: value` lines between the opening `---` pair."""
    lines = text.splitlines()
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        return {}
    block = lines[1 : lines.index("---", 1)]
    return dict(
        line.split(": ", 1)
        for line in block
        if ": " in line and not line.startswith(" ")
    )


class Skills(unittest.TestCase):
    def test_there_is_a_skill_to_check(self):
        self.assertTrue(list(SKILLS.glob("*/SKILL.md")), f"no skill under {SKILLS}")

    def test_every_skill_carries_a_name_matching_its_directory_and_a_description(self):
        for path in sorted(SKILLS.glob("*/SKILL.md")):
            with self.subTest(skill=path.parent.name):
                fields = frontmatter(path.read_text(encoding="utf-8"))
                name = fields.get("name", "")
                self.assertTrue(NAME.match(name) and len(name) <= 64, name)
                self.assertEqual(name, path.parent.name)
                description = fields.get("description", "").strip()
                self.assertTrue(0 < len(description) <= 1024, description)

    def test_a_directory_under_skills_is_a_skill(self):
        for path in sorted(SKILLS.iterdir()):
            with self.subTest(path=path.name):
                self.assertTrue((path / "SKILL.md").is_file(), path)


if __name__ == "__main__":
    unittest.main()
