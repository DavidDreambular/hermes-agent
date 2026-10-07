"""Behavior checks for the fixed owner deployment admission boundary."""
import importlib.util
from pathlib import Path

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
                    valid.replace("DavidDreambular", "other-owner"), valid.replace("refs/heads/main,", "")]:
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
