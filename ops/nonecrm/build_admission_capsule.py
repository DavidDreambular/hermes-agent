#!/usr/bin/env python3
"""Build the fixed six-member bootstrap package from clean protected canonical source."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

from hermes_admission import verify_canonical
from hermes_admission_bootstrap import GH_SHA, ROOTS_SHA


def build(tools, output):
    repo = Path(__file__).resolve().parents[2]
    git = lambda *args: subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    target = git("rev-parse", "HEAD")
    if git("status", "--porcelain") or git("rev-parse", "refs/remotes/origin/main") != target:
        raise ValueError("capsule requires clean latest canonical source")
    verify_canonical(target)
    entries = {"installer.py": (repo / "ops/nonecrm/hermes_admission_bootstrap.py").read_bytes(),
               "admission.py": (repo / "ops/nonecrm/hermes_admission.py").read_bytes(),
               "gh": (tools / "gh").read_bytes(), "trusted-root.jsonl": (tools / "trusted-root.jsonl").read_bytes()}
    digest = lambda data: hashlib.sha256(data).hexdigest()
    if digest(entries["gh"]) != GH_SHA or digest(entries["trusted-root.jsonl"]) != ROOTS_SHA:
        raise ValueError("public verifier resources are not the reviewed pinned bytes")
    policy = {"schema": 1, "enabled": True, "service": "nonecrm-hermes-agent", "repository": "DavidDreambular/hermes-agent",
              "gh_sha256": GH_SHA, "roots_sha256": ROOTS_SHA, "admission_sha256": digest(entries["admission.py"])}
    entries["policy.json"] = json.dumps(policy, sort_keys=True).encode()
    entries["manifest.json"] = json.dumps({name: digest(data) for name, data in entries.items()}, sort_keys=True).encode()
    name = "hermes-admission-v1-midpoints-vps.tar.gz"
    path = output / name
    if path.exists() or path.is_symlink():
        raise ValueError("preserve existing capsule; do not overwrite")
    with path.open("xb") as archive:
        with tarfile.open(fileobj=archive, mode="w:gz") as package:
            for member, data in entries.items():
                info = tarfile.TarInfo(member)
                info.size, info.mode, info.mtime = len(data), 0o600, 0
                package.addfile(info, io.BytesIO(data))
    with Path(str(path) + ".sha256").open("x", encoding="utf-8") as checksum:
        checksum.write(f"{digest(path.read_bytes())}  {name}\n")
    print(f"Built bounded capsule source={target} sha256={digest(path.read_bytes())}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.tools, args.output)
