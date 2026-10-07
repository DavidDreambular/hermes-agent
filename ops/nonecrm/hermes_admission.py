#!/usr/bin/python3
"""Fixed, independently signed artifact admission; never imports or deploys images."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
import urllib.request

REPO = "DavidDreambular/hermes-agent"
WORKFLOW = f"{REPO}/.github/workflows/nonecrm-native-runtime.yml"
TOOLS = Path("/usr/local/libexec/production-guard")
POLICY = Path("/etc/production-guard/hermes-admission.json")
DELEGATION = Path("/etc/production-guard/delegation.conf")
STATE = Path("/var/lib/production-guard/hermes-artifacts")
JOURNAL = Path("/var/lib/production-guard/hermes-bootstrap-transaction.json")
PR_PARAMETERS = {"required_approving_review_count": 0, "dismiss_stale_reviews_on_push": False,
                 "required_reviewers": [], "require_code_owner_review": False, "require_last_push_approval": False,
                 "required_review_thread_resolution": True, "require_extra_approval_for_unattributed_changes": True,
                 "allowed_merge_methods": ["merge", "squash", "rebase"]}


def stage_path(target):
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise ValueError("invalid source revision")
    return STATE / target


def validate_image(value, target):
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("invalid image metadata")
    image = value[0]
    config = image.get("Config", {})
    if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict) or not isinstance(image.get("Id"), str):
        raise ValueError("invalid image configuration")
    labels = config.get("Labels", {})
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("Id", ""))
            or image.get("Os") != "linux" or image.get("Architecture") != "amd64"
            or type(image.get("Size")) is not int or not 0 < image["Size"] <= 1_500_000_000
            or config.get("User") != "10000:10000"
            or config.get("Entrypoint") != ["/opt/hermes/.venv/bin/hermes"]
            or config.get("Cmd") != ["gateway"]
            or labels.get("org.opencontainers.image.revision") != target
            or labels.get("org.opencontainers.image.source") != f"https://github.com/{REPO}"):
        raise ValueError("image violates the fixed native runtime policy")
    return image["Id"]


def verification_args(artifact, bundle, target):
    return [str(TOOLS / "hermes-gh"), "attestation", "verify", str(artifact),
            "--bundle", str(bundle), "--custom-trusted-root", str(TOOLS / "hermes-trusted-root.jsonl"),
            "--repo", REPO, "--source-ref", "refs/heads/main",
            "--source-digest", target, "--signer-digest", target, "--deny-self-hosted-runners",
            "--cert-identity", f"https://github.com/{WORKFLOW}@refs/heads/main",
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--format", "json"]


def trusted_parents(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted file parent")


def secure_digest(path, limit, mode=None):
    trusted_parents(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or not 0 < info.st_size <= limit):
            raise ValueError("unsafe admission file")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise ValueError("incorrect installed file mode")
        digest = hashlib.sha256()
        consumed = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            consumed += len(block)
            if consumed > limit:
                raise ValueError("admission file grew beyond its limit")
            digest.update(block)
        return digest.hexdigest()


def secure_directory(path):
    for item in [*reversed(path.parents), path]:
        if not item.exists() and not item.is_symlink():
            item.mkdir(mode=0o700)
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe admission directory")


def source_json(endpoint):
    request = urllib.request.Request(f"https://api.github.com/repos/{REPO}/{endpoint}",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "hermes-admission"})
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("oversized source response")
    return json.loads(raw)


def verify_canonical(target):
    branch = source_json("branches/main")
    if branch.get("protected") is not True or branch.get("commit", {}).get("sha") != target:
        raise ValueError("source is not the exact protected canonical commit")
    ruleset = source_json("rulesets/24670342")
    rules = {rule.get("type"): rule for rule in ruleset.get("rules", [])}
    if (ruleset.get("enforcement") != "active" or ruleset.get("bypass_actors") != []
            or "refs/heads/main" not in ruleset.get("conditions", {}).get("ref_name", {}).get("include", [])
            or ruleset.get("conditions", {}).get("ref_name", {}).get("exclude") != []
            or set(rules) != {"pull_request", "deletion", "non_fast_forward"}
            or rules["pull_request"].get("parameters") != PR_PARAMETERS):
        raise ValueError("canonical source protection changed")


def validate_delegation(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("invalid superior delegation")
        key, value = line.split("=", 1)
        if key in values:
            raise ValueError("duplicate superior delegation key")
        values[key] = value
    if (values.get("VERSION") != "1" or values.get("ENABLED") != "true"
            or values.get("HOST_ID") != "midpoints-vps" or values.get("ALLOWED_REPO_OWNER") != REPO.split("/")[0]
            or "refs/heads/main" not in values.get("ALLOWED_CANONICAL_REFS", "").split(",")):
        raise ValueError("superior delegation revoked or narrowed")


def delegation_snapshot():
    digest = secure_digest(DELEGATION, 16384, 0o600)
    validate_delegation(DELEGATION.read_text(encoding="utf-8"))
    return digest


def committed_bootstrap(policy):
    digest = secure_digest(JOURNAL, 16384, 0o600)
    transaction = json.loads(JOURNAL.read_text(encoding="utf-8"))
    manifest = transaction.get("manifest", {})
    if (transaction.get("phase") != "committed" or manifest.get("admission.py") != policy["admission_sha256"]
            or manifest.get("gh") != policy["gh_sha256"] or manifest.get("trusted-root.jsonl") != policy["roots_sha256"]):
        raise ValueError("bootstrap activation is incomplete")
    return digest


def receipt_data(target, image_id, hashes, policy_digest, bootstrap_digest):
    return {"source": target, "image": image_id, "hashes": hashes, "repository": REPO,
            "verified_by": "github-sigstore-hosted-build", "workflow": WORKFLOW,
            "verified_at": int(time.time()), "policy_sha256": policy_digest, "bootstrap_sha256": bootstrap_digest}


def admit(target, prepare=False):
    if os.geteuid() != 0 or socket.gethostname() != "MidPointsIA":
        raise ValueError("installed admission requires root")
    os.umask(0o077)
    stage = stage_path(target)
    superior_digest = delegation_snapshot()
    policy_digest = secure_digest(POLICY, 16384, 0o600)
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    if (policy.get("schema") != 1 or policy.get("enabled") is not True
            or policy.get("service") != "nonecrm-hermes-agent" or policy.get("repository") != REPO):
        raise ValueError("admission is not delegated for this service")
    bootstrap_digest = committed_bootstrap(policy)
    for name, key, mode in [("hermes-gh", "gh_sha256", 0o755), ("hermes-trusted-root.jsonl", "roots_sha256", 0o644),
                            ("hermes-artifact-admit", "admission_sha256", 0o755)]:
        if secure_digest(TOOLS / name, 100_000_000, mode) != policy.get(key):
            raise ValueError("installed verifier hash changed")
    secure_directory(STATE)
    lock = os.open(STATE / ".admission.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unsafe admission lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_canonical(target)
        secure_directory(stage)
        if prepare:
            print(stage)
            return
        hashes = {name: secure_digest(stage / name, limit) for name, limit in
                  [("image.tar.gz", 1_000_000_000), ("image.json", 1_000_000), ("attestation.json", 16_000_000)]}
        with tempfile.TemporaryDirectory(prefix=".verify-", dir=STATE) as home:
            env = {"HOME": home, "GH_CONFIG_DIR": home, "PATH": "/usr/bin:/bin", "GH_HOST": "github.com"}
            for name in ["image.tar.gz", "image.json"]:
                subprocess.run(verification_args(stage / name, stage / "attestation.json", target),
                               env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if any(secure_digest(stage / name, 1_000_000_000) != digest for name, digest in hashes.items()):
            raise ValueError("artifact changed during verification")
        image_id = validate_image(json.loads((stage / "image.json").read_text(encoding="utf-8")), target)
        verify_canonical(target)
        if (delegation_snapshot() != superior_digest or secure_digest(POLICY, 16384, 0o600) != policy_digest
                or committed_bootstrap(policy) != bootstrap_digest):
            raise ValueError("delegation changed during verification")
        receipt = receipt_data(target, image_id, hashes, policy_digest, bootstrap_digest)
        descriptor, temporary = tempfile.mkstemp(prefix=".receipt-", dir=stage)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, stage / "admitted.json")
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        print(f"Admitted independently verified native image {image_id} at {target}")
    finally:
        os.close(lock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "admit"])
    parser.add_argument("target")
    arguments = parser.parse_args()
    try:
        admit(arguments.target, arguments.action == "prepare")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Hermes admission rejected: {type(error).__name__}\n")
