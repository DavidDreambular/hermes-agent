"""Fail-closed cleanup for Kanban-owned scratch workspaces.

Scratch paths can contain a linked Git worktree created by a delegated
worker. Removing that directory with ``shutil.rmtree`` frees the files but
leaves the shared repository's worktree registry pointing at a missing path.
This module recognizes only clean, registered, branch-attached worktrees and
asks Git to unregister them before deleting the enclosing scratch directory.
Standalone clones, detached worktrees, dirty worktrees, symlinks, and paths
outside the board's managed scratch root are deliberately left for review.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
from typing import Optional


_GENERATED_DIRS = frozenset({
    ".next", ".turbo", "node_modules", "coverage", "dist", "build",
    ".venv", "venv",
})
_GIT_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class ScratchWorkspacePlan:
    """Read-only decision for one task scratch directory."""

    path: Path
    reclaimable_bytes: int
    reason: Optional[str] = None
    manager_path: Optional[Path] = None
    linked_worktree_path: Optional[Path] = None

    @property
    def safe(self) -> bool:
        return self.reason is None


def _git(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_GIT_TIMEOUT_SECONDS,
        check=False,
    )


def _workspace_size(path: Path) -> tuple[int, Optional[str]]:
    total = 0
    errors: list[str] = []

    def onerror(exc: OSError) -> None:
        errors.append(str(exc))

    for root, dirs, files in os.walk(path, topdown=True, followlinks=False, onerror=onerror):
        current = Path(root)
        dirs[:] = [
            name
            for name in dirs
            if not (current / name).is_symlink()
        ]
        for name in files:
            candidate = current / name
            try:
                info = candidate.lstat()
            except OSError as exc:
                errors.append(str(exc))
                continue
            if not candidate.is_symlink() and candidate.is_file():
                total += info.st_size
    return total, ("workspace_size_unavailable" if errors else None)


def _find_git_marker(path: Path) -> tuple[Optional[Path], Optional[str]]:
    markers: list[Path] = []
    for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
        current = Path(root)
        if ".git" in dirs:
            marker = current / ".git"
            dirs.remove(".git")
            markers.append(marker)
            continue
        if ".git" in files:
            markers.append(current / ".git")
            dirs[:] = []
            continue
        dirs[:] = [
            name
            for name in dirs
            if name not in _GENERATED_DIRS
            and not (current / name).is_symlink()
        ]
    if not markers:
        return None, None
    if len(markers) != 1:
        return None, "multiple_nested_git_repositories"
    marker = markers[0]
    if marker.is_symlink():
        return marker, "git_metadata_is_symlink"
    if marker.is_dir():
        return marker, "standalone_git_repository_requires_manual_review"
    if not marker.is_file():
        return marker, "git_metadata_unreadable"
    return marker, None


def _linked_worktree_manager(
    linked_path: Path,
) -> tuple[Optional[Path], Optional[str]]:
    try:
        repo_result = _git(linked_path, "rev-parse", "--show-toplevel")
        if repo_result.returncode != 0:
            return None, "git_worktree_probe_failed"
        repo_root = Path(repo_result.stdout.strip()).resolve(strict=True)
        if repo_root != linked_path.resolve(strict=True):
            return None, "git_marker_does_not_match_repository_root"

        branch = _git(linked_path, "symbolic-ref", "--quiet", "--short", "HEAD")
        if branch.returncode != 0 or not branch.stdout.strip():
            return None, "detached_git_worktree_requires_manual_review"

        status = _git(linked_path, "status", "--porcelain", "--untracked-files=all")
        if status.returncode != 0:
            return None, "git_status_probe_failed"
        if status.stdout.strip():
            return None, "dirty_git_worktree"

        listing = _git(linked_path, "worktree", "list", "--porcelain")
        if listing.returncode != 0:
            return None, "git_worktree_list_failed"
        records: list[dict[str, str | bool]] = []
        for block in listing.stdout.strip().split("\n\n"):
            record: dict[str, str | bool] = {}
            for line in block.splitlines():
                if line.startswith("worktree "):
                    record["path"] = line[len("worktree "):]
                elif line == "locked" or line.startswith("locked "):
                    record["locked"] = True
            if record.get("path"):
                records.append(record)
        target = str(repo_root)
        matching = next(
            (record for record in records if str(Path(str(record["path"])).resolve()) == target),
            None,
        )
        if matching is None:
            return None, "git_worktree_not_registered"
        if matching.get("locked"):
            return None, "git_worktree_locked"

        manager = next(
            (
                Path(str(record["path"])).resolve()
                for record in records
                if str(Path(str(record["path"])).resolve()) != target
                and Path(str(record["path"])).is_dir()
            ),
            None,
        )
        if manager is None:
            return None, "git_worktree_manager_unavailable"
        return manager, None
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return None, "git_worktree_probe_failed"


def plan_scratch_workspace_cleanup(
    path: Path,
    *,
    workspaces_root: Path,
) -> ScratchWorkspacePlan:
    """Inspect one task path without mutating disk or Git metadata."""
    raw_path = path.expanduser()
    root = workspaces_root.expanduser().resolve(strict=False)
    if raw_path.is_symlink():
        return ScratchWorkspacePlan(raw_path, 0, "workspace_root_is_symlink")
    try:
        resolved = raw_path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError):
        return ScratchWorkspacePlan(raw_path, 0, "workspace_outside_managed_root_or_missing")
    if not relative.parts:
        return ScratchWorkspacePlan(resolved, 0, "refuse_to_remove_workspaces_root")
    if not resolved.is_dir():
        return ScratchWorkspacePlan(resolved, 0, "workspace_is_not_directory")

    size, size_error = _workspace_size(resolved)
    if size_error:
        return ScratchWorkspacePlan(resolved, size, size_error)
    marker, marker_error = _find_git_marker(resolved)
    if marker_error:
        return ScratchWorkspacePlan(resolved, size, marker_error)
    if marker is None:
        return ScratchWorkspacePlan(resolved, size)

    # A scratch task may wrap exactly one linked worktree (for example, a
    # delegated worker's repo checkout). Do not remove sibling files or more
    # complex trees automatically: they may be handoff artifacts.
    git_root = marker.parent.resolve(strict=True)
    try:
        relative_repo = git_root.relative_to(resolved)
    except ValueError:
        return ScratchWorkspacePlan(resolved, size, "nested_git_path_escaped_workspace")
    if relative_repo.parts:
        current = resolved
        for part in relative_repo.parts:
            try:
                children = list(current.iterdir())
            except OSError:
                return ScratchWorkspacePlan(resolved, size, "workspace_tree_unreadable")
            expected = current / part
            if len(children) != 1 or children[0] != expected:
                return ScratchWorkspacePlan(
                    resolved, size, "scratch_workspace_has_sibling_artifacts"
                )
            current = expected

    manager, manager_error = _linked_worktree_manager(git_root)
    if manager_error:
        return ScratchWorkspacePlan(resolved, size, manager_error)
    return ScratchWorkspacePlan(
        resolved,
        size,
        manager_path=manager,
        linked_worktree_path=git_root,
    )


def remove_scratch_workspace(plan: ScratchWorkspacePlan) -> tuple[bool, str]:
    """Remove a previously inspected workspace without force or following links."""
    if not plan.safe:
        return False, plan.reason or "workspace_not_safe"
    if plan.linked_worktree_path is not None:
        if plan.manager_path is None:
            return False, "git_worktree_manager_unavailable"
        try:
            result = _git(
                plan.manager_path,
                "worktree",
                "remove",
                str(plan.linked_worktree_path),
            )
        except (OSError, subprocess.SubprocessError):
            return False, "git_worktree_remove_failed"
        if result.returncode != 0:
            return False, "git_worktree_remove_failed"
    if plan.path.exists():
        try:
            shutil.rmtree(plan.path)
        except OSError:
            return False, "scratch_workspace_remove_failed"
    if plan.path.exists():
        return False, "scratch_workspace_still_exists"
    return True, "removed"
