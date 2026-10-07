"""Fixed program against a real Unix HTTP boundary in an isolated root container."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import threading
import time

import pytest


@pytest.mark.linux_only
@pytest.mark.parametrize("failure", [None, "signature", "candidate-exit", "rename", "journal", "probe", "exited-journal", "live-success", "pause-response"])
def test_isolated_fixed_recovery_transaction(failure):
    if os.geteuid() != 0 or socket.gethostname() != "MidPointsIA" or not Path("/.dockerenv").exists():
        pytest.skip("requires dedicated isolated Docker root fixture without host socket")
    endpoint = Path("/var/run/docker.sock")
    assert not endpoint.exists(), "never replace a real engine socket"
    source = Path("/opt/production-sources/nonecrm-hermes-agent-source")
    assert not source.exists()
    target, expected = "a" * 40, "2bd1977d8fad185c9b4be47884f7e87f1add0ce3"
    live = failure in {"live-success", "pause-response"}
    failed = failure not in {None, "live-success"}
    if live:
        expected = "c" * 40
    old_id = "cf415bbe164a37938c9b655a112fba51150206818c1d1c7e4595c86fd090b2d0"
    old_image = "sha256:b2ee88947e66c349dbefeae5c6e1fd846d7b4d5f938fe2d3f04aeeecc09c11fc"
    image_id = "sha256:" + "b" * 64
    home = Path("/var/lib/docker/volumes/1abf8bf156c0b133516d33681e3088327c993b670b773e608a729cc77194fe1e/_data")
    stage = Path("/var/lib/production-guard/hermes-artifacts") / target
    config = Path("/etc/production-guard/services.d/nonecrm-hermes-agent--production.conf")
    # Exact observed old config bytes, fetched as nonsecret fixture input.
    fixture_config = Path(__file__).parents[1] / "fixtures/nonecrm/sidecar.conf"
    if not fixture_config.is_file():
        pytest.skip("requires exact nonsecret legacy configuration fixture")
    assert hashlib.sha256(fixture_config.read_bytes()).hexdigest() == "233f3142744224c04dabe408629d7927b82d8d0443656913a770fa01454d2e15"
    for path in [source / "ops/nonecrm", home, stage, config.parent, Path("/opt/apps"), Path("/run/production-guard"), Path("/usr/local/libexec/production-guard")]:
        path.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(fixture_config, config)
    profile = Path(__file__).parents[2] / "ops/nonecrm/config.example.yaml"
    shutil.copyfile(profile, source / "ops/nonecrm/config.example.yaml")
    os.chown(home, 10000, 10000)
    (home / "history.txt").write_text("preserve-existing-state")
    (stage / "image.tar.gz").write_bytes(b"fixture-only-boundary-image")
    (stage / "attestation.json").write_text("fixture-only-verifier-boundary")
    (stage / "image.json").write_text(json.dumps([{"Id": image_id, "Size": 10000}]))
    hashes = {name: hashlib.sha256((stage / name).read_bytes()).hexdigest() for name in ["image.tar.gz", "image.json", "attestation.json"]}
    policy = Path("/etc/production-guard/hermes-admission.json")
    journal = stage.parent.parent / "hermes-bootstrap-transaction.json"
    policy.write_text("fixture-policy")
    journal.write_text("fixture-journal")
    (stage / "admitted.json").write_text(json.dumps({"source": target, "repository": "DavidDreambular/hermes-agent", "verified_by": "github-sigstore-hosted-build", "image": image_id, "hashes": hashes, "verified_at": int(time.time()), "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(), "bootstrap_sha256": hashlib.sha256(journal.read_bytes()).hexdigest()}))
    (stage.parent / ".admission.lock").touch(mode=0o600)
    Path("/run/production-guard/nonecrm-hermes-agent--production.active").write_text(f"TARGET={target}\n")
    scripts = {"/usr/bin/git": f'#!/bin/sh\ncase "$*" in *rev-parse*) echo {target};; esac\n',
               "/usr/bin/docker": "#!/bin/sh\ncat >/dev/null\n",
               "/usr/local/libexec/production-guard/hermes-artifact-admit": "#!/bin/sh\nexit " + ("1" if failure == "signature" else "0") + "\n"}
    for path, data in scripts.items():
        Path(path).write_text(data)
        Path(path).chmod(0o755)
    if not Path("/usr/bin/python3").exists():
        Path("/usr/bin/python3").symlink_to("/usr/local/bin/python3")
    old = {"Id": old_id, "Name": "/nonecrm-hermes-agent", "Image": old_image, "State": {"Status": "running" if live else "exited", "Running": live},
           "Config": {"Labels": {"org.opencontainers.image.revision": expected, "nonecrm.managed": "native-hermes-v1"}}, "Mounts": [{"Destination": "/opt/data", "Source": str(home)}]}
    operations, new = [], {}
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            method, path, _ = self.rfile.readline().decode().split()
            length = 0
            while (line := self.rfile.readline()) != b"\r\n":
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            body = json.loads(self.rfile.read(length)) if length else None
            operations.append((method, path, body))
            status, response = 200, {}
            if "/exec/" in path and path.endswith("/start"):
                response = None
                encoded = b'HERMES_PROBE={"provider":"openrouter","model":"openai/gpt-6-luna","disk_status":"degraded"}\n'
            elif "/exec/" in path:
                response = {"ExitCode": 1 if failure == "probe" else 0}
            elif path.endswith("/exec"):
                response = {"Id": "fixture-exec"}
            elif path.endswith("containers/nonecrm-app/json"):
                response = {"Config": {"Env": ["HERMES_AGENT_API_KEY=fixture-key-1234567890", "OPENROUTER_API_KEY=fixture-key-0987654321"]}}
            elif "/images/" in path:
                response = {"Id": image_id, "Config": {"Labels": {"org.opencontainers.image.revision": target}}}
            elif "/containers/create?" in path:
                new.update({"Id": "new-id", "Image": body["Image"], "State": {"Running": failure != "candidate-exit", "Health": {"Status": "healthy"}}, "NetworkSettings": {"Networks": {}}})
                response = {"Id": "new-id"}
            elif "/rename?" in path:
                if failure == "rename":
                    status = 500
                elif old_id in path:
                    old["Name"] = "/nonecrm-hermes-agent" if path.endswith("name=nonecrm-hermes-agent") else "/preserved"
                else:
                    new["Name"] = "/nonecrm-hermes-agent" if "name=nonecrm-hermes-agent&" in path or path.endswith("name=nonecrm-hermes-agent") else "/candidate"
                    if failure in {"journal", "exited-journal"} and new["Name"] == "/nonecrm-hermes-agent":
                        (Path("/opt/apps/nonecrm-hermes-native") / target / "transaction.json.new").touch()
                        if failure == "exited-journal":
                            new["State"]["Running"] = False
            elif "/networks/" in path:
                new["NetworkSettings"]["Networks"]["nonecrm_nonecrm-network"] = {}
            elif path.endswith("/json"):
                response = old if old_id in path else new if "new-id" in path or new.get("Name") == "/nonecrm-hermes-agent" else old
            elif "/pause" in path or "/unpause" in path:
                old["State"]["Paused"] = "/unpause" not in path
                if failure == "pause-response" and old["State"]["Paused"]:
                    return  # The effect happened, but the HTTP response is lost.
            elif "/stop" in path:
                state = old["State"] if old_id in path else new["State"]
                if not state["Running"]:
                    status = 304
                state["Running"] = False
            if response is not None:
                encoded = json.dumps(response).encode()
            self.wfile.write(f"HTTP/1.1 {status} OK\r\nContent-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode() + encoded)
    server = socketserver.UnixStreamServer(str(endpoint), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    program = Path(__file__).parents[2] / "ops/production-guard/nonecrm-hermes-agent-deploy"
    try:
        result = subprocess.run(["/bin/bash", str(program)], env={"PATH": "/usr/bin:/bin", "SERVICE": "nonecrm-hermes-agent", "ENVIRONMENT": "production", "TARGET_REVISION": target, "EXPECTED_REVISION": expected}, capture_output=True, text=True, timeout=20)
        assert result.returncode == (1 if failed else 0), result.stdout + result.stderr
        assert (home / "history.txt").read_text() == "preserve-existing-state"
        assert "fixture-key" not in result.stdout + result.stderr
        exposed = any("/networks/" in path for _, path, _ in operations)
        assert exposed is (not failed)
        assert old["State"].get("Paused", False) is False
        if new and failed:
            assert new["State"]["Running"] is False
            assert old["Name"] == "/nonecrm-hermes-agent"
        if not failed:
            transaction = json.loads((Path("/opt/apps/nonecrm-hermes-native") / target / "transaction.json").read_text())
            assert transaction["traffic_committed"] and transaction["phase"] == "private-ready"
            assert transaction["old_runtime_usable"] is live
            assert Path(transaction["backup"], "hermes-state.tar.gz").exists()
    finally:
        server.shutdown()
        server.server_close()
        endpoint.unlink()
        for path in [source, home.parent.parent.parent, Path("/opt/apps/nonecrm-hermes-native"), stage.parent.parent, config.parent, Path("/run/production-guard")]:
            if path.exists():
                shutil.rmtree(path)
