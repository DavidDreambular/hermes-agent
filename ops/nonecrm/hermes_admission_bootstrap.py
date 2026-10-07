#!/usr/bin/python3
"""Fixed trust-anchor extension for one Hermes service; preserves all existing guards."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import tarfile
import tempfile

EXPECTED = {
    "/usr/local/bin/production-guard": "49e8b20e89b08ca7fb2f87df16086ad7b18a965bc3919bf126da2e8509b0b62b",
    "/usr/local/bin/production-guard-onboard-run": "3eed6ba766531c2d7ea6efcfbb5a8527d2e61b446f241ccf7bf56e105a1cdba1",
    "/usr/local/bin/production-guard-source-sync-run": "465dd2424ec686b99a428cb44fda1145b7c68da4ebb1c68e84ba976c2f5fa6bf",
    "/etc/production-guard/delegation.conf": "084117e0361ac366625555f08aeb1fef26b68c605f19af7588f4718f773dfd37",
}
GH_SHA = "7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b"
ROOTS_SHA = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
DESTINATIONS = {
    "admission.py": ("/usr/local/libexec/production-guard/hermes-artifact-admit", 0o755),
    "gh": ("/usr/local/libexec/production-guard/hermes-gh", 0o755),
    "trusted-root.jsonl": ("/usr/local/libexec/production-guard/hermes-trusted-root.jsonl", 0o644),
    "policy.json": ("/etc/production-guard/hermes-admission.json", 0o600),
}
JOURNAL = Path("/var/lib/production-guard/hermes-bootstrap-transaction.json")
LOCK = Path("/run/production-guard/onboarding.lock")
STATE = Path("/var/lib/production-guard/hermes-artifacts")
AUDIT = Path("/var/lib/production-guard/hermes-bootstrap-audit.jsonl")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parents_safe(path):
    for parent in path.parents:
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
                raise ValueError("unsafe install parent")


def atomic_bytes(path, data, mode):
    parents_safe(path)
    for directory in reversed([path.parent, *path.parent.parents]):
        if not directory.exists():
            directory.mkdir(mode=0o755)
            sync_directory(directory.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".hermes-bootstrap-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if Path(temporary).exists():
            Path(temporary).unlink()
            sync_directory(path.parent)


def root_regular(path, mode=None):
    parents_safe(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or info.st_mode & 0o022
            or mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise ValueError("unsafe installed file")


def rollback(transaction, manifest):
    # Only files absent before this exact transaction can be retired.
    for name in reversed(transaction["created"]):
        if name not in DESTINATIONS:
            raise ValueError("unsafe recovery transaction")
        path = Path(DESTINATIONS[name][0])
        if path.exists() or path.is_symlink():
            root_regular(path, DESTINATIONS[name][1])
            if digest(path) != manifest[name]:
                raise ValueError("recovery found changed component")
            path.unlink()
            sync_directory(path.parent)


def digest(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 100_000_000:
            raise ValueError("unsafe package file")
        return hashlib.file_digest(source, "sha256").hexdigest()


def install(authorization, package_sha):
    if os.geteuid() != 0 or socket.gethostname() != "MidPointsIA":
        raise ValueError("bootstrap requires the exact owner host")
    if (not authorization.startswith("owner:permanent-fleet:20261006:")
            or not re.fullmatch(r"[A-Za-z0-9._:@/-]{8,200}", authorization)
            or not re.fullmatch(r"[0-9a-f]{64}", package_sha)):
        raise ValueError("invalid bootstrap identity")
    os.umask(0o077)
    payload = Path(__file__).resolve().parent
    manifest = json.loads((payload / "manifest.json").read_text(encoding="utf-8"))
    allowed = set(DESTINATIONS) | {"installer.py", "manifest.json"}
    if {item.name for item in payload.iterdir()} != allowed or set(manifest) != allowed - {"manifest.json"}:
        raise ValueError("package contains unapproved entries")
    if any(digest(payload / name) != expected for name, expected in manifest.items()):
        raise ValueError("package contents changed")
    archive = payload.parent / "hermes-admission-v1-midpoints-vps.tar.gz"
    root_regular(archive, 0o600)
    if digest(archive) != package_sha:
        raise ValueError("package archive compare-and-swap failed")
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        if len(members) != len(allowed) or {item.name for item in members} != allowed:
            raise ValueError("unexpected capsule members")
        for item in members:
            if not item.isfile() or not 0 < item.size <= 100_000_000:
                raise ValueError("unsafe capsule member")
            if package.extractfile(item).read() != (payload / item.name).read_bytes():
                raise ValueError("extracted capsule differs from pinned archive")
    if manifest["gh"] != GH_SHA or manifest["trusted-root.jsonl"] != ROOTS_SHA:
        raise ValueError("unapproved signature verifier or trust roots")
    policy = json.loads((payload / "policy.json").read_text(encoding="utf-8"))
    snapshot = policy.get("source_policy_snapshot")
    if (not isinstance(snapshot, dict) or snapshot.get("id") != 24670342
            or snapshot.get("source") != "DavidDreambular/hermes-agent" or snapshot.get("bypass_actors") != []
            or snapshot.get("enforcement") != "active" or not snapshot.get("updated_at")
            or snapshot.get("conditions", {}).get("ref_name") != {"include": ["refs/heads/main"], "exclude": []}
            or {item.get("type") for item in snapshot.get("rules", [])} != {"pull_request", "deletion", "non_fast_forward"}):
        raise ValueError("invalid bounded owner source-policy observation")
    if {key: value for key, value in policy.items() if key != "source_policy_snapshot"} != {"schema": 1, "enabled": True, "service": "nonecrm-hermes-agent",
                  "repository": "DavidDreambular/hermes-agent", "gh_sha256": GH_SHA,
                  "roots_sha256": ROOTS_SHA, "admission_sha256": manifest["admission.py"]}:
        raise ValueError("package attempts to expand delegated scope")
    lock_path = LOCK
    parents_safe(lock_path)
    lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    admission_lock = None
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError("unsafe bootstrap lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = STATE
        parents_safe(state)
        state.mkdir(mode=0o700, exist_ok=True)
        sync_directory(state.parent)
        info = state.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("unsafe admission state")
        admission_lock = os.open(state / ".admission.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(admission_lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unsafe admission lock")
        fcntl.flock(admission_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name, expected in EXPECTED.items():
            path = Path(name)
            root_regular(path, 0o600 if name.endswith(".conf") else 0o755)
            if digest(path) != expected:
                raise ValueError("installed guard compare-and-swap failed")
        old = {}
        if JOURNAL.exists() or JOURNAL.is_symlink():
            root_regular(JOURNAL, 0o600)
            old = json.loads(JOURNAL.read_text(encoding="utf-8"))
            if old.get("phase") == "installing":
                if old.get("package") != package_sha or old.get("manifest") != manifest:
                    raise ValueError("another bootstrap transaction needs recovery")
                rollback(old, manifest)
        missing = []
        for name, (destination, mode) in DESTINATIONS.items():
            path = Path(destination)
            parents_safe(path)
            if path.exists() or path.is_symlink():
                root_regular(path, mode)
                if digest(path) != manifest[name]:
                    raise ValueError("existing admission component differs")
            else:
                missing.append(name)
        if not missing and old.get("phase") == "committed" and old.get("manifest") == manifest and old.get("package") == package_sha:
            print("Bounded Hermes admission already committed; no activation state changed.")
            return
        transaction = {"phase": "installing", "package": package_sha, "manifest": manifest, "created": missing}
        atomic_bytes(JOURNAL, json.dumps(transaction, sort_keys=True).encode(), 0o600)
        audit = AUDIT
        parents_safe(audit)
        if audit.exists() or audit.is_symlink():
            root_regular(audit, 0o600)
        try:
            for name, (destination, mode) in DESTINATIONS.items():
                if name in missing:
                    atomic_bytes(Path(destination), (payload / name).read_bytes(), mode)
                root_regular(Path(destination), mode)
                if digest(Path(destination)) != manifest[name]:
                    raise ValueError("installed verifier differs from approved package")
        except Exception:
            rollback(transaction, manifest)
            transaction["phase"] = "rolled-back"
            atomic_bytes(JOURNAL, json.dumps(transaction, sort_keys=True).encode(), 0o600)
            raise
        # Atomic audit replacement cannot leave a partial appended JSON tail.
        previous = audit.read_bytes() if audit.exists() else b""
        if len(previous) > 1_000_000 or previous and not previous.endswith(b"\n"):
            raise ValueError("unsafe existing audit history")
        for line in previous.splitlines():
            json.loads(line)
        record = {"authorization": authorization, "package_sha256": package_sha, "installed": manifest,
                  "prior_components": "absent-or-identical", "preserved_guard_hashes": EXPECTED}
        atomic_bytes(audit, previous + json.dumps(record, sort_keys=True).encode() + b"\n", 0o600)
        transaction["phase"] = "committed"
        atomic_bytes(JOURNAL, json.dumps(transaction, sort_keys=True).encode(), 0o600)
        print("Installed bounded Hermes admission; existing guard, source runner and policy unchanged.")
    finally:
        if admission_lock is not None:
            os.close(admission_lock)
        os.close(lock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-id", choices=["midpoints-vps"], required=True)
    parser.add_argument("--authorization-ref", required=True)
    parser.add_argument("--package-sha", required=True)
    args = parser.parse_args()
    try:
        install(args.authorization_ref, args.package_sha)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Hermes bootstrap rejected: {type(error).__name__}\n")
