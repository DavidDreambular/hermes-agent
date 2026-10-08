"""Link configuration and OCI-manifest identities inside an already admitted archive."""
import hashlib
import json
import re
import tarfile


def archive_image_refs(path, config_id):
    if not isinstance(config_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", config_id):
        raise ValueError("invalid admitted configuration identity")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 1024 or len({member.name for member in members}) != len(members):
            raise ValueError("ambiguous OCI archive")

        def read(name):
            member = archive.getmember(name)
            if not member.isfile() or not 0 < member.size <= 1_000_000:
                raise ValueError("unsafe OCI identity member")
            return archive.extractfile(member).read()

        index = json.loads(read("index.json"))
        if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
            raise ValueError("expected one OCI image manifest")
        manifest_id = index["manifests"][0].get("digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_id):
            raise ValueError("invalid OCI manifest identity")
        manifest_bytes = read("blobs/sha256/" + manifest_id.removeprefix("sha256:"))
        if hashlib.sha256(manifest_bytes).hexdigest() != manifest_id.removeprefix("sha256:"):
            raise ValueError("OCI manifest content changed")
        manifest = json.loads(manifest_bytes)
        if manifest.get("schemaVersion") != 2 or manifest.get("config", {}).get("digest") != config_id:
            raise ValueError("OCI manifest is not linked to the admitted configuration")
        config_bytes = read("blobs/sha256/" + config_id.removeprefix("sha256:"))
        if hashlib.sha256(config_bytes).hexdigest() != config_id.removeprefix("sha256:"):
            raise ValueError("admitted configuration content changed")
        config = json.loads(config_bytes)
        if config.get("os") != "linux" or config.get("architecture") != "amd64":
            raise ValueError("OCI configuration platform mismatch")
    return [manifest_id, config_id]
