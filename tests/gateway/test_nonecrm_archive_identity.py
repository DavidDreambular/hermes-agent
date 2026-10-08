"""Content-addressed OCI identity must remain bound across Docker image stores."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest


def component():
    path = Path(__file__).parents[2] / "ops/nonecrm/archive_identity.py"
    assert path.is_file()
    spec = importlib.util.spec_from_file_location("archive_identity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(path, corrupt=False):
    config = b'{"architecture":"amd64","os":"linux"}'
    config_sha = hashlib.sha256(config).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + config_sha}, "layers": []}).encode()
    manifest_sha = hashlib.sha256(manifest).hexdigest()
    index = json.dumps({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + manifest_sha}]}).encode()
    entries = {"index.json": index, "blobs/sha256/" + manifest_sha: b"corrupt" if corrupt else manifest,
               "blobs/sha256/" + config_sha: config}
    with tarfile.open(path, "w:gz") as package:
        for name, data in entries.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            package.addfile(item, io.BytesIO(data))
    return "sha256:" + config_sha, "sha256:" + manifest_sha


def test_accepts_only_config_and_linked_manifest_id(tmp_path):
    path = tmp_path / "image.tar.gz"
    config_id, manifest_id = fixture(path)
    assert component().archive_image_refs(path, config_id) == [manifest_id, config_id]


def test_rejects_changed_manifest_and_unrelated_config(tmp_path):
    path = tmp_path / "image.tar.gz"
    config_id, _ = fixture(path, corrupt=True)
    with pytest.raises(ValueError):
        component().archive_image_refs(path, config_id)
    fixture(path)
    with pytest.raises(ValueError):
        component().archive_image_refs(path, "sha256:" + "f" * 64)
