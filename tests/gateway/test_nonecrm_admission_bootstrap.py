"""Real root filesystem transactions, run only in an isolated container/CI host."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import tarfile

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[2] / f"ops/nonecrm/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fixture(monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("real root ownership checks require isolated root CI/container")
    root = Path(tempfile.mkdtemp(prefix="hermes-fixture-", dir="/root"))
    module = load("hermes_admission_bootstrap")
    payload = root / "payload"
    payload.mkdir(mode=0o700)
    module_path = Path(module.__file__)
    shutil.copyfile(module_path, payload / "installer.py")
    monkeypatch.setattr(module, "__file__", str(payload / "installer.py"))
    monkeypatch.setattr(module.socket, "gethostname", lambda: "MidPointsIA")
    expected = {}
    for index in range(4):
        path = root / f"old-{index}" / ("delegation.conf" if index == 3 else "guard")
        path.parent.mkdir()
        path.write_bytes(f"unchanged-component-{index}".encode())
        path.chmod(0o600 if index == 3 else 0o755)
        expected[str(path)] = module.digest(path)
    monkeypatch.setattr(module, "EXPECTED", expected)
    destinations = {name: (str(root / "installed" / name), mode) for name, (_, mode) in module.DESTINATIONS.items()}
    monkeypatch.setattr(module, "DESTINATIONS", destinations)
    journal = root / "state" / "journal.json"
    monkeypatch.setattr(module, "JOURNAL", journal)
    monkeypatch.setattr(module, "LOCK", root / "run" / "onboarding.lock", raising=False)
    monkeypatch.setattr(module, "STATE", root / "state" / "artifacts", raising=False)
    monkeypatch.setattr(module, "AUDIT", root / "state" / "audit.jsonl", raising=False)
    (root / "run").mkdir()
    (root / "state").mkdir()
    for name in ["admission.py", "gh", "trusted-root.jsonl"]:
        (payload / name).write_bytes(f"test-only-{name}".encode())
    sha = lambda name: hashlib.sha256((payload / name).read_bytes()).hexdigest()
    monkeypatch.setattr(module, "GH_SHA", sha("gh"))
    monkeypatch.setattr(module, "ROOTS_SHA", sha("trusted-root.jsonl"))
    policy = {"schema": 1, "enabled": True, "service": "nonecrm-hermes-agent", "repository": "DavidDreambular/hermes-agent",
              "gh_sha256": sha("gh"), "roots_sha256": sha("trusted-root.jsonl"), "admission_sha256": sha("admission.py"),
              "source_policy_snapshot": {"id": 24670342, "source": "DavidDreambular/hermes-agent", "enforcement": "active",
                  "bypass_actors": [], "updated_at": "2026-10-07T00:00:00Z", "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                  "rules": [{"type": name} for name in ["pull_request", "deletion", "non_fast_forward"]]}}
    (payload / "policy.json").write_text(json.dumps(policy))
    manifest = {name: sha(name) for name in ["installer.py", *destinations]}
    (payload / "manifest.json").write_text(json.dumps(manifest))
    archive = root / "hermes-admission-v1-midpoints-vps.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        for path in payload.iterdir():
            package.add(path, arcname=path.name)
    archive.chmod(0o600)
    yield module, root, manifest
    shutil.rmtree(root)


def install(module):
    archive = Path(module.__file__).parent.parent / "hermes-admission-v1-midpoints-vps.tar.gz"
    module.install("owner:permanent-fleet:20261006:isolated-test", module.digest(archive))


def preserved(module):
    assert all(module.digest(Path(path)) == sha for path, sha in module.EXPECTED.items())


def test_root_install_commits_audit_and_preserves_existing_guards(fixture):
    module, root, manifest = fixture
    install(module)
    assert json.loads(module.JOURNAL.read_text())["phase"] == "committed"
    assert json.loads((root / "state/audit.jsonl").read_text())["installed"] == manifest
    for name, (path, mode) in module.DESTINATIONS.items():
        module.root_regular(Path(path), mode)
        assert module.digest(Path(path)) == manifest[name]
    preserved(module)
    install(module)
    preserved(module)


@pytest.mark.parametrize("unsafe", ["symlink", "writable", "hardlink"])
def test_root_install_rejects_unsafe_existing_destination(fixture, unsafe):
    module, root, _ = fixture
    path = Path(module.DESTINATIONS["admission.py"][0])
    path.parent.mkdir()
    if unsafe == "symlink":
        path.symlink_to(root / "outside")
    else:
        path.write_bytes(b"unsafe")
        path.chmod(0o777 if unsafe == "writable" else 0o755)
        if unsafe == "hardlink":
            os.link(path, root / "linked")
    with pytest.raises(ValueError):
        install(module)
    preserved(module)


def test_crash_is_recoverable_without_trusting_partial_activation(fixture, monkeypatch):
    module, _, _ = fixture
    original = module.atomic_bytes
    policy = Path(module.DESTINATIONS["policy.json"][0])
    def crash(path, data, mode):
        if path == policy:
            raise SystemExit("simulated process crash")
        original(path, data, mode)
    monkeypatch.setattr(module, "atomic_bytes", crash)
    with pytest.raises(SystemExit):
        install(module)
    assert json.loads(module.JOURNAL.read_text())["phase"] == "installing"
    assert not policy.exists()
    monkeypatch.setattr(module, "atomic_bytes", original)
    install(module)
    assert json.loads(module.JOURNAL.read_text())["phase"] == "committed"
    preserved(module)


def test_partial_audit_write_cannot_corrupt_committed_audit(fixture, monkeypatch):
    module, root, _ = fixture
    audit = root / "state/audit.jsonl"
    audit.write_text('{"prior":true}\n')
    audit.chmod(0o600)
    original = module.os.fdopen
    class BrokenWriter:
        def __init__(self, descriptor, *args, **kwargs):
            self.stream = original(descriptor, *args, **kwargs)
        def __enter__(self):
            self.stream.__enter__()
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def __getattr__(self, name):
            return getattr(self.stream, name)
        def write(self, value):
            if b'"prior"' in value:
                self.stream.write(value[:10])
                self.stream.flush()
                raise OSError("partial audit write")
            return self.stream.write(value)
    def fdopen(descriptor, *args, **kwargs):
        if args and args[0] == "wb" and Path(os.readlink(f"/proc/self/fd/{descriptor}")).parent == audit.parent:
            return BrokenWriter(descriptor, *args, **kwargs)
        return original(descriptor, *args, **kwargs)
    monkeypatch.setattr(module.os, "fdopen", fdopen)
    with pytest.raises(OSError):
        install(module)
    assert json.loads(module.JOURNAL.read_text())["phase"] != "committed"
    assert audit.read_text() == '{"prior":true}\n'
    monkeypatch.setattr(module.os, "fdopen", original)
    install(module)
    assert all(isinstance(json.loads(line), dict) for line in audit.read_text().splitlines())
