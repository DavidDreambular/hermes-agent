"""Tests for safe Kanban workspace garbage collection."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import time

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _gc_args(*extra: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="hermes")
    subparsers = parser.add_subparsers(dest="command")
    kc.build_parser(subparsers)
    return parser.parse_args(["kanban", "gc", *extra])


def _terminal_task(
    *,
    status: str,
    completed_at: int,
    workspace_path: Path | None = None,
) -> tuple[str, Path]:
    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title=f"GC fixture {status}",
            initial_status="running",
            workspace_kind="scratch",
        )
        path = workspace_path or (kb.workspaces_root() / task_id)
        path.mkdir(parents=True, exist_ok=True)
        conn.execute(
            "UPDATE tasks SET status=?, workspace_path=?, completed_at=? WHERE id=?",
            (status, str(path), completed_at, task_id),
        )
    return task_id, path


def test_archiving_records_terminal_timestamp_for_retention(kanban_home):
    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="archive timestamp fixture",
            initial_status="running",
            workspace_kind="scratch",
        )

    before_archive = int(time.time())
    with kb.connect_closing() as conn:
        assert kb.archive_task(conn, task_id)
        row = conn.execute(
            "SELECT status, completed_at FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()

    assert row["status"] == "archived"
    assert row["completed_at"] is not None
    assert row["completed_at"] >= before_archive


def test_gc_uses_archived_event_for_legacy_terminal_timestamp(kanban_home, capsys):
    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="legacy archive timestamp fixture",
            initial_status="running",
            workspace_kind="scratch",
        )
        workspace = kb.workspaces_root() / task_id
        workspace.mkdir(parents=True)
        kb.set_workspace_path(conn, task_id, str(workspace))
        assert kb.archive_task(conn, task_id)
        conn.execute(
            "UPDATE tasks SET completed_at = NULL WHERE id = ?",
            (task_id,),
        )
        conn.execute(
            "UPDATE task_events SET created_at = ? "
            "WHERE task_id = ? AND kind = 'archived'",
            (int(time.time()) - 31 * 24 * 3600, task_id),
        )

    result = kc.kanban_command(
        _gc_args(
            "--workspace-retention-days", "30",
            "--event-retention-days", "36500",
            "--log-retention-days", "36500",
        )
    )

    capsys.readouterr()
    assert result == 0
    assert not workspace.exists()


def test_gc_dry_run_reports_old_workspace_without_removing_it(
    kanban_home, capsys, monkeypatch
):
    now = int(time.time())
    task_id, workspace = _terminal_task(
        status="archived",
        completed_at=now - 31 * 24 * 3600,
    )
    payload = workspace / "generated-cache.bin"
    payload.write_bytes(b"x" * 4096)
    monkeypatch.setattr(kb, "gc_events", lambda *_a, **_k: pytest.fail("dry-run wrote events"))
    monkeypatch.setattr(kb, "gc_worker_logs", lambda *_a, **_k: pytest.fail("dry-run removed logs"))

    args = _gc_args("--dry-run", "--workspace-retention-days", "30")

    result = kc.kanban_command(args)

    output = capsys.readouterr().out
    assert result == 0
    assert task_id in output
    assert "would remove" in output.lower()
    assert "4096" in output
    assert payload.exists()


def test_gc_keeps_recent_archived_workspace(kanban_home, capsys):
    now = int(time.time())
    task_id, workspace = _terminal_task(
        status="archived",
        completed_at=now - 29 * 24 * 3600,
    )
    payload = workspace / "keep.txt"
    payload.write_text("retained", encoding="utf-8")

    result = kc.kanban_command(
        _gc_args("--dry-run", "--workspace-retention-days", "30")
    )

    output = capsys.readouterr().out
    assert result == 0
    assert task_id not in output
    assert payload.read_text(encoding="utf-8") == "retained"


def test_gc_removes_old_clean_linked_worktree_but_keeps_its_branch(
    kanban_home, tmp_path, capsys
):
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "GC Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "gc@example.invalid"],
        check=True,
    )
    (repo / "README.md").write_text("tracked source\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "source"], check=True)

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="GC linked worktree fixture",
            initial_status="running",
            workspace_kind="scratch",
        )
    workspace = kb.workspaces_root() / task_id
    linked = workspace / "checkout"
    workspace.mkdir(parents=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "worktree", "add", "--quiet", "-b",
            "gc-retained-branch", str(linked), "HEAD",
        ],
        check=True,
    )
    with kb.connect_closing() as conn:
        conn.execute(
            "UPDATE tasks SET status='archived', workspace_path=?, completed_at=? WHERE id=?",
            (str(workspace), 1_700_000_000, task_id),
        )

    result = kc.kanban_command(
        _gc_args("--workspace-retention-days", "30", "--event-retention-days", "36500", "--log-retention-days", "36500")
    )

    capsys.readouterr()
    assert result == 0
    assert not workspace.exists()
    assert subprocess.run(
        ["git", "-C", str(repo), "show-ref", "--verify", "refs/heads/gc-retained-branch"],
        capture_output=True,
    ).returncode == 0
    registered = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert str(linked) not in registered


def test_gc_skips_dirty_linked_worktree_and_preserves_changes(
    kanban_home, tmp_path, capsys
):
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "GC Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "gc@example.invalid"],
        check=True,
    )
    (repo / "README.md").write_text("tracked source\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "source"], check=True)

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="GC dirty worktree fixture",
            initial_status="running",
            workspace_kind="scratch",
        )
    workspace = kb.workspaces_root() / task_id
    linked = workspace / "checkout"
    workspace.mkdir(parents=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "worktree", "add", "--quiet", "-b",
            "gc-dirty-branch", str(linked), "HEAD",
        ],
        check=True,
    )
    with kb.connect_closing() as conn:
        conn.execute(
            "UPDATE tasks SET status='archived', workspace_path=?, completed_at=? WHERE id=?",
            (str(workspace), 1_700_000_000, task_id),
        )
    user_change = linked / "WIP.txt"
    user_change.write_text("preserve me\n", encoding="utf-8")

    result = kc.kanban_command(
        _gc_args("--workspace-retention-days", "30", "--event-retention-days", "36500", "--log-retention-days", "36500")
    )

    output = capsys.readouterr().out
    assert result == 0
    assert "dirty" in output.lower()
    assert user_change.read_text(encoding="utf-8") == "preserve me\n"


def test_complete_task_unregisters_nested_linked_worktree(kanban_home, tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "GC Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "gc@example.invalid"],
        check=True,
    )
    (repo / "README.md").write_text("tracked source\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "source"], check=True)

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="completion cleans its task worktree",
            initial_status="running",
            workspace_kind="scratch",
        )
        workspace = kb.workspaces_root() / task_id
        linked = workspace / "checkout"
        workspace.mkdir(parents=True)
        subprocess.run(
            [
                "git", "-C", str(repo), "worktree", "add", "--quiet", "-b",
                "gc-completion-branch", str(linked), "HEAD",
            ],
            check=True,
        )
        kb.set_workspace_path(conn, task_id, str(workspace))

        assert kb.complete_task(conn, task_id, result="done")

    assert not workspace.exists()
    registered = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert str(linked) not in registered
    assert subprocess.run(
        ["git", "-C", str(repo), "show-ref", "--verify", "refs/heads/gc-completion-branch"],
        capture_output=True,
    ).returncode == 0


def test_gc_removes_old_plain_scratch_workspace(kanban_home, capsys):
    now = int(time.time())
    task_id, workspace = _terminal_task(
        status="done",
        completed_at=now - 31 * 24 * 3600,
    )
    (workspace / "generated-cache.bin").write_bytes(b"x" * 1024)

    result = kc.kanban_command(
        _gc_args(
            "--workspace-retention-days", "30",
            "--event-retention-days", "36500",
            "--log-retention-days", "36500",
        )
    )

    output = capsys.readouterr().out
    assert result == 0
    assert task_id in output
    assert not workspace.exists()


def test_gc_refuses_workspace_path_outside_managed_root(kanban_home, tmp_path, capsys):
    now = int(time.time())
    external = tmp_path / "precious-source"
    external.mkdir()
    sentinel = external / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    task_id, _workspace = _terminal_task(
        status="archived",
        completed_at=now - 31 * 24 * 3600,
        workspace_path=external,
    )

    result = kc.kanban_command(
        _gc_args(
            "--workspace-retention-days", "30",
            "--event-retention-days", "36500",
            "--log-retention-days", "36500",
        )
    )

    output = capsys.readouterr().out
    assert result == 0
    assert task_id in output
    assert "outside" in output.lower() or "refus" in output.lower()
    assert sentinel.read_text(encoding="utf-8") == "keep"
