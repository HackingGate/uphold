"""Fixtures, and the one test that lives beside its fixture.

This directory is a package for a mechanical reason. `python3 -m unittest
discover -s tests` walks a subdirectory only when it is importable, so without
this file `test_promotion_corpus.py` is not found, not run, and not reported --
which is the same silence the test it hides exists to prevent.
"""
