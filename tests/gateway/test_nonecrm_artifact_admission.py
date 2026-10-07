"""Behavior checks for the fixed owner deployment admission boundary."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile

import pytest


def component():
    path = Path(__file__).parents[2] / "ops/nonecrm/hermes_admission.py"
    assert path.is_file(), "fixed admission component must exist"
    spec = importlib.util.spec_from_file_location("hermes_admission", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def image(target):
    return [{"Id": "sha256:" + "b" * 64, "Os": "linux", "Architecture": "amd64", "Size": 540000000,
             "Config": {"User": "10000:10000", "Entrypoint": ["/opt/hermes/.venv/bin/hermes"], "Cmd": ["gateway"],
                        "Labels": {"org.opencontainers.image.revision": target,
                                   "org.opencontainers.image.source": "https://github.com/DavidDreambular/hermes-agent"}}}]


def test_signed_metadata_must_bind_expected_runtime():
    module = component()
    target = "a" * 40
    assert module.validate_image(image(target), target) == "sha256:" + "b" * 64
    for field, value in [("Os", "windows"), ("Architecture", "arm64"), ("Size", True), ("Size", 3_000_000_000)]:
        metadata = image(target)
        metadata[0][field] = value
        with pytest.raises(ValueError):
            module.validate_image(metadata, target)
    for field, value in [("User", "root"), ("Cmd", ["sh"]), ("Entrypoint", ["/bin/sh"])]:
        metadata = image(target)
        metadata[0]["Config"][field] = value
        with pytest.raises(ValueError):
            module.validate_image(metadata, target)
    with pytest.raises(ValueError):
        module.validate_image(image("c" * 40), target)


def test_verifier_policy_binds_both_identity_and_source():
    module = component()
    argv = module.verification_args(Path("/stage/image.tar.gz"), Path("/stage/attestation.json"), "a" * 40)
    assert "--deny-self-hosted-runners" in argv
    assert "--signer-workflow" not in argv  # Mutually exclusive with exact certificate identity.
    assert argv[argv.index("--source-digest") + 1] == "a" * 40
    assert argv[argv.index("--signer-digest") + 1] == "a" * 40
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/main"
    assert argv[argv.index("--repo") + 1] == "DavidDreambular/hermes-agent"
    assert "@refs/heads/main" in argv[argv.index("--cert-identity") + 1]
    assert argv[argv.index("--custom-trusted-root") + 1].startswith("/usr/local/libexec/production-guard/")


def test_stage_keys_reject_arbitrary_paths_and_short_revisions():
    module = component()
    assert module.stage_path("a" * 40).name == "a" * 40
    for value in ["../escape", "a" * 8, "A" * 40, "a" * 40 + ";id"]:
        with pytest.raises(ValueError):
            module.stage_path(value)


def test_superior_delegation_revocation_is_inherited():
    module = component()
    valid = "VERSION=1\nENABLED=true\nHOST_ID=midpoints-vps\nALLOWED_REPO_OWNER=DavidDreambular\nALLOWED_CANONICAL_REFS=refs/heads/main,refs/heads/master\n"
    module.validate_delegation(valid)
    for changed in [valid.replace("ENABLED=true", "ENABLED=false"), valid.replace("midpoints-vps", "other-host"),
                    valid.replace("DavidDreambular", "other-owner"), valid.replace("refs/heads/main,", ""),
                    "\n".join(line for line in valid.splitlines() if not line.startswith("ALLOWED_CANONICAL_REFS="))]:
        with pytest.raises(ValueError):
            module.validate_delegation(changed)


def test_excluded_canonical_branch_cannot_pass_protection(monkeypatch):
    module = component()
    target = "a" * 40
    monkeypatch.setattr(module, "source_json", lambda endpoint: {"protected": True, "commit": {"sha": target}}
                        if endpoint == "branches/main" else {"enforcement": "active", "bypass_actors": [],
                        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": ["refs/heads/main"]}},
                        "rules": [{"type": name} for name in ["pull_request", "deletion", "non_fast_forward"]]})
    with pytest.raises(ValueError):
        module.verify_canonical(target)


def test_receipt_binds_verification_time_and_active_policy(monkeypatch):
    module = component()
    monkeypatch.setattr(module.time, "time", lambda: 123456)
    result = module.receipt_data("a" * 40, "sha256:" + "b" * 64, {"image.json": "c" * 64}, "d" * 64, "e" * 64)
    assert result["verified_at"] == 123456
    assert result["policy_sha256"] == "d" * 64
    assert result["bootstrap_sha256"] == "e" * 64


def test_anonymous_policy_requires_current_snapshot_after_signature_verification(monkeypatch):
    module = component()
    target = "a" * 40
    policy = {"id": 24670342, "source": module.REPO, "updated_at": "2026-10-07T00:00:00Z", "enforcement": "active",
              "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
              "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "pull_request", "parameters": module.PR_PARAMETERS}]}
    monkeypatch.setattr(module, "source_json", lambda endpoint: {"protected": True, "commit": {"sha": target}} if endpoint == "branches/main" else policy)
    module.verify_canonical(target, prepare=True)  # Creates staging only, never an admission receipt.
    with pytest.raises(ValueError, match="root-owned"):
        module.verify_canonical(target)
    snapshot = {**policy, "bypass_actors": []}
    module.verify_canonical(target, snapshot)
    policy["updated_at"] = "2026-10-08T00:00:00Z"
    with pytest.raises(ValueError, match="revision"):
        module.verify_canonical(target, snapshot)


def test_live_anonymous_github_policy_matches_public_snapshot():
    snapshot_path = Path("/signed-fixture/source-policy.json")
    if os.geteuid() != 0 or not snapshot_path.exists():
        pytest.skip("requires hosted isolated-root live policy fixture")
    module = component()
    target = module.source_json("branches/main")["commit"]["sha"]
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    public = module.source_json("rulesets/24670342")
    differences = [key for key in ["updated_at", "enforcement", "conditions", "rules", "source"] if snapshot.get(key) != public.get(key)]
    assert not differences, f"authenticated/anonymous policy shapes differ: {differences}"
    # Real public HTTPS validates staging/protection shape, NOT private actors or
    # an image approval. The fixed owner capsule separately captures that policy.
    module.verify_canonical(target, prepare=True)


def test_root_admit_real_signed_bundle_end_to_end(monkeypatch):
    fixture = Path("/signed-fixture")
    if os.geteuid() != 0 or not (fixture / "image.json").exists():
        pytest.skip("requires isolated root and genuine hosted signed artifact fixture")
    module = component()
    root = Path(tempfile.mkdtemp(prefix="signed-admit-", dir="/root"))
    target = json.loads((fixture / "image.json").read_text())[0]["Config"]["Labels"]["org.opencontainers.image.revision"]
    for key, value in {"STATE": root / "state", "TOOLS": root / "tools", "POLICY": root / "policy", "DELEGATION": root / "delegation", "JOURNAL": root / "journal"}.items():
        monkeypatch.setattr(module, key, value)
    module.TOOLS.mkdir()
    sources = [(Path("/verifier-fixture/gh"), "hermes-gh", "gh_sha256", 0o755),
               (Path("/verifier-fixture/trusted-root.jsonl"), "hermes-trusted-root.jsonl", "roots_sha256", 0o644),
               (Path(module.__file__), "hermes-artifact-admit", "admission_sha256", 0o755)]
    policy = {"schema": 1, "enabled": True, "service": "nonecrm-hermes-agent", "repository": module.REPO}
    source_policy = {"id": 24670342, "source": module.REPO, "updated_at": "2026-10-07T00:00:00Z", "enforcement": "active",
                     "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                     "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "pull_request", "parameters": module.PR_PARAMETERS}]}
    policy["source_policy_snapshot"] = {**source_policy, "bypass_actors": []}
    for source, name, key, mode in sources:
        shutil.copyfile(source, module.TOOLS / name)
        (module.TOOLS / name).chmod(mode)
        policy[key] = module.secure_digest(module.TOOLS / name, 100_000_000)
    module.POLICY.write_text(json.dumps(policy))
    module.DELEGATION.write_text("VERSION=1\nENABLED=true\nHOST_ID=midpoints-vps\nALLOWED_REPO_OWNER=DavidDreambular\nALLOWED_CANONICAL_REFS=refs/heads/main\n")
    module.JOURNAL.write_text(json.dumps({"phase": "committed", "manifest": {"admission.py": policy["admission_sha256"], "gh": policy["gh_sha256"], "trusted-root.jsonl": policy["roots_sha256"]}}))
    for path in [module.POLICY, module.DELEGATION, module.JOURNAL]:
        path.chmod(0o600)
    public = source_policy  # Simulates the actor-redacted API, not empty actors.
    rules = public["rules"]
    monkeypatch.setattr(module, "source_json", lambda endpoint: {"protected": True, "commit": {"sha": target}} if endpoint == "branches/main" else public)
    try:
        module.admit(target, prepare=True)
        stage = module.stage_path(target)
        for name in ["image.tar.gz", "image.json", "attestation.json"]:
            shutil.copyfile(fixture / name, stage / name)
        module.admit(target)
        receipt = json.loads((stage / "admitted.json").read_text())
        assert receipt["source"] == target and receipt["image"].startswith("sha256:")
        assert receipt["policy_sha256"] == module.secure_digest(module.POLICY, 16384)
        (stage / "admitted.json").unlink()
        (stage / "image.json").write_text("corrupted signed metadata")
        with pytest.raises(module.subprocess.CalledProcessError):
            module.admit(target)
        assert not (stage / "admitted.json").exists()
        rules[2]["parameters"] = {**module.PR_PARAMETERS, "required_review_thread_resolution": False}
        with pytest.raises(ValueError, match="protection"):
            module.verify_canonical(target)
    finally:
        shutil.rmtree(root)
