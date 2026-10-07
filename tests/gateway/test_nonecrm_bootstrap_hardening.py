"""Additional isolated-root activation regressions using the shared fixture."""
import json
import importlib.util
from pathlib import Path

import pytest
spec = importlib.util.spec_from_file_location("bootstrap_fixture", Path(__file__).with_name("test_nonecrm_admission_bootstrap.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
fixture, install, preserved = shared.fixture, shared.install, shared.preserved


def test_rewritten_extracted_capsule_cannot_self_authorize(fixture):
    module, root, _ = fixture
    payload = root / "payload"
    (payload / "admission.py").write_bytes(b"changed untrusted verifier")
    policy = json.loads((payload / "policy.json").read_text())
    policy["admission_sha256"] = module.digest(payload / "admission.py")
    (payload / "policy.json").write_text(json.dumps(policy))
    manifest = {name: module.digest(payload / name) for name in ["installer.py", *module.DESTINATIONS]}
    (payload / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="pinned archive"):
        install(module)
    assert not module.JOURNAL.exists()
    preserved(module)


def test_idempotent_rerun_cannot_revoke_committed_activation(fixture, monkeypatch):
    module, root, _ = fixture
    install(module)
    before = module.JOURNAL.read_bytes()
    (root / "state/audit.jsonl").write_text("invalid audit tail")
    monkeypatch.setattr(module, "atomic_bytes", lambda *args: pytest.fail("no-op must not rewrite activation"))
    install(module)
    assert module.JOURNAL.read_bytes() == before
    preserved(module)


def test_new_destination_directory_fsyncs_its_parent(fixture, monkeypatch):
    module, root, _ = fixture
    calls = []
    original = module.sync_directory
    def fsync(path):
        calls.append(path)
        original(path)
    monkeypatch.setattr(module, "sync_directory", fsync)
    install(module)
    assert root in calls  # The installed directory entry is durable in its parent.
    preserved(module)


def test_root_compare_and_swap_rejects_changed_guard(fixture):
    module, _, _ = fixture
    Path(next(iter(module.EXPECTED))).write_bytes(b"changed")
    with pytest.raises(ValueError, match="compare-and-swap"):
        install(module)
    assert not module.JOURNAL.exists()


def test_install_failure_rolls_back_only_new_components(fixture, monkeypatch):
    module, _, _ = fixture
    original = module.atomic_bytes
    policy = Path(module.DESTINATIONS["policy.json"][0])
    def fail_policy(path, data, mode):
        if path == policy:
            raise OSError("simulated disk write failure")
        original(path, data, mode)
    monkeypatch.setattr(module, "atomic_bytes", fail_policy)
    with pytest.raises(OSError):
        install(module)
    assert json.loads(module.JOURNAL.read_text())["phase"] == "rolled-back"
    assert all(not Path(path).exists() for path, _ in module.DESTINATIONS.values())
    preserved(module)
