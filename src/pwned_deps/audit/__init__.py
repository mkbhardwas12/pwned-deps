"""Forensic on-disk file scanning.

`pwned-deps audit-repo PATH` walks a directory tree and looks for files
matching the structured `file_iocs` blocks in the campaign feed —
either by SHA-256 (high confidence) or by path-hint (suggestive). This
is for the *post-incident* question SecurityBridge / Wiz both
emphasise: "have these files landed on our developer machines or build
runners as IDE persistence after the lockfile match was already
remediated?"

This module is import-only — the CLI binding lives in `pwned_deps.cli`.
"""
