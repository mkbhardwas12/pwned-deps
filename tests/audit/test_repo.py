"""Tests for `pwned_deps.audit.repo` and the `audit-repo` CLI command.

We never check real malicious bytes into the repo (BUILD_BRIEF §2.8).
Instead each test builds a synthetic feed pointing at a benign file
whose SHA-256 we compute on the fly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from click.testing import CliRunner

from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.audit.repo import audit_repo, collect_file_iocs
from pwned_deps.cli import main as cli_main


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_feed(tmp_path: Path, campaign: dict) -> Path:
    feed_path = tmp_path / "synthetic-feed.json"
    feed_path.write_text(
        json.dumps({"version": 1, "campaigns": [campaign]}),
        encoding="utf-8",
    )
    return feed_path


def _feed_with(campaign: dict) -> ExtrasFeed:
    return ExtrasFeed.from_dict({"version": 1, "campaigns": [campaign]})


def test_collect_file_iocs_pulls_block_from_bundled_feed() -> None:
    feed = ExtrasFeed.from_bundled()
    iocs = collect_file_iocs(feed)
    # The Mini Shai-Hulud campaign ships seven file_iocs (5 path-only +
    # 3 distinct execution.js hashes; setup.mjs hash appears twice but
    # under different path hints, so 7 entries total).
    sha_only_hashes = {i.sha256 for i in iocs if i.sha256}
    assert "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34" in sha_only_hashes
    assert any(i.path_hint == ".vscode/tasks.json" for i in iocs)


def test_audit_finds_sha256_match(tmp_path: Path) -> None:
    payload = b"this-is-a-benign-test-payload\n"
    target = tmp_path / "deep" / "nested" / "weird-file.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(payload)

    feed = _feed_with(
        {
            "id": "TEST-2026-0001",
            "name": "synthetic test campaign",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [
                {
                    "sha256": _sha256(payload),
                    "description": "synthetic bytes used by pwned-deps test suite",
                }
            ],
        }
    )

    hits = audit_repo(tmp_path, feed)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.path == target
    assert hit.matched_by == "sha256"
    assert hit.is_confirmed
    assert hit.ioc.campaign_id == "TEST-2026-0001"


def test_audit_finds_sha256_plus_path_match(tmp_path: Path) -> None:
    payload = b"persistence-marker\n"
    target = tmp_path / ".claude" / "settings.json"
    target.parent.mkdir()
    target.write_bytes(payload)

    feed = _feed_with(
        {
            "id": "TEST-2026-0002",
            "name": "synthetic ide-persistence",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [
                {
                    "path_hint": ".claude/settings.json",
                    "sha256": _sha256(payload),
                    "description": "claude settings hook",
                }
            ],
        }
    )

    hits = audit_repo(tmp_path, feed)
    assert len(hits) == 1
    assert hits[0].matched_by == "sha256+path"
    assert hits[0].is_confirmed


def test_audit_path_only_match_is_suspect_not_confirmed(tmp_path: Path) -> None:
    target = tmp_path / ".vscode" / "tasks.json"
    target.parent.mkdir()
    target.write_bytes(b"// modified content, hash will not match\n")

    feed = _feed_with(
        {
            "id": "TEST-2026-0003",
            "name": "path-only test",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [
                {
                    "path_hint": ".vscode/tasks.json",
                    "sha256": "0" * 64,
                    "description": "expected hash differs",
                }
            ],
        }
    )

    hits = audit_repo(tmp_path, feed)
    assert len(hits) == 1
    assert hits[0].matched_by == "path"
    assert not hits[0].is_confirmed


def test_audit_skips_node_modules_and_git(tmp_path: Path) -> None:
    payload = b"would-match-if-walked\n"
    sha = _sha256(payload)

    # Identical payload in three places: one walked, two skipped.
    walked = tmp_path / "src" / "evil.bin"
    walked.parent.mkdir()
    walked.write_bytes(payload)
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "evil.bin").write_bytes(payload)
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".git" / "objects" / "evil.bin").write_bytes(payload)

    feed = _feed_with(
        {
            "id": "TEST-2026-0004",
            "name": "skip-test",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [{"sha256": sha, "description": "x"}],
        }
    )

    hits = audit_repo(tmp_path, feed)
    assert len(hits) == 1
    assert hits[0].path == walked


def test_audit_skips_oversized_files(tmp_path: Path) -> None:
    payload = b"A" * 1024
    target = tmp_path / "small.bin"
    target.write_bytes(payload)
    big = tmp_path / "big.bin"
    big.write_bytes(b"A" * 4096)

    feed = _feed_with(
        {
            "id": "TEST-2026-0005",
            "name": "size-cap",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [
                {"sha256": _sha256(payload), "description": "tiny"},
                {"sha256": _sha256(b"A" * 4096), "description": "huge"},
            ],
        }
    )

    hits = audit_repo(tmp_path, feed, max_file_bytes=2048)
    matched_paths = {h.path for h in hits}
    assert target in matched_paths
    assert big not in matched_paths


def test_audit_does_not_follow_symlinks(tmp_path: Path) -> None:
    payload = b"symlink-target\n"
    real_dir = tmp_path.parent / "outside-audit-root"
    real_dir.mkdir(exist_ok=True)
    real_file = real_dir / "evil.bin"
    real_file.write_bytes(payload)
    try:
        link = tmp_path / "shortcut.bin"
        link.symlink_to(real_file)

        feed = _feed_with(
            {
                "id": "TEST-2026-0006",
                "name": "symlink-test",
                "ecosystem": "npm",
                "packages": [],
                "file_iocs": [{"sha256": _sha256(payload), "description": "x"}],
            }
        )

        hits = audit_repo(tmp_path, feed)
        assert hits == []
    finally:
        if real_file.exists():
            real_file.unlink()
        if real_dir.exists():
            real_dir.rmdir()


def test_audit_repo_cli_text_output_exit_1_on_confirmed(tmp_path: Path) -> None:
    payload = b"cli-text-test\n"
    target = tmp_path / "weird.bin"
    target.write_bytes(payload)

    feed_path = _write_feed(
        tmp_path,
        {
            "id": "TEST-2026-CLI-1",
            "name": "cli text test",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [{"sha256": _sha256(payload), "description": "match"}],
        },
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        ["audit-repo", str(tmp_path), "--feed-file", str(feed_path)],
    )
    assert result.exit_code == 1, result.output
    assert "CONFIRMED" in result.output
    assert "TEST-2026-CLI-1" in result.output


def test_audit_repo_cli_json_output(tmp_path: Path) -> None:
    payload = b"cli-json-test\n"
    target = tmp_path / "evidence.bin"
    target.write_bytes(payload)

    feed_path = _write_feed(
        tmp_path,
        {
            "id": "TEST-2026-CLI-2",
            "name": "cli json test",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [{"sha256": _sha256(payload), "description": "x"}],
        },
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        ["audit-repo", str(tmp_path), "--format", "json", "--feed-file", str(feed_path)],
    )
    assert result.exit_code == 1, result.output
    payload_out = json.loads(result.output)
    assert payload_out["schema_version"] == "1.0"
    assert payload_out["command"] == "audit-repo"
    assert payload_out["summary"]["confirmed_sha256"] == 1
    assert payload_out["hits"][0]["confirmed"] is True
    assert payload_out["hits"][0]["matched_by"] == "sha256"


def test_audit_repo_cli_clean_exit_0(tmp_path: Path) -> None:
    (tmp_path / "harmless.txt").write_text("nothing to see here", encoding="utf-8")

    feed_path = _write_feed(
        tmp_path,
        {
            "id": "TEST-2026-CLI-3",
            "name": "no-match",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [{"sha256": "0" * 64, "description": "won't match"}],
        },
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        ["audit-repo", str(tmp_path), "--feed-file", str(feed_path)],
    )
    assert result.exit_code == 0, result.output
    assert "CLEAN" in result.output


def test_audit_repo_cli_path_only_exit_2(tmp_path: Path) -> None:
    target = tmp_path / ".claude" / "execution.js"
    target.parent.mkdir()
    target.write_text("// modified, hash differs", encoding="utf-8")

    feed_path = _write_feed(
        tmp_path,
        {
            "id": "TEST-2026-CLI-4",
            "name": "path-only",
            "ecosystem": "npm",
            "packages": [],
            "file_iocs": [
                {
                    "path_hint": ".claude/execution.js",
                    "sha256": "0" * 64,
                    "description": "differs",
                }
            ],
        },
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        ["audit-repo", str(tmp_path), "--feed-file", str(feed_path)],
    )
    assert result.exit_code == 2, result.output
    assert "SUSPECT" in result.output
