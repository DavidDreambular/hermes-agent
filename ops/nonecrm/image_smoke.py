"""Exercise the built native API image without authentication or inference."""
import os
from pathlib import Path
import sqlite3

from gateway.platforms.api_server import APIServerAdapter
from hermes_cli.build_info import get_code_identity
from providers import get_provider_profile
from run_agent import AIAgent


def main():
    expected = os.environ["EXPECTED_SOURCE_REVISION"]
    identity = get_code_identity(refresh=True)
    assert identity["sha"] == expected and identity["source"] == "build-file"
    assert identity["version"]
    assert sqlite3.sqlite_version_info >= (3, 51, 3)
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE VIRTUAL TABLE docs USING fts5(content, tokenize='trigram')")
        database.execute("INSERT INTO docs VALUES ('hermes')")
        assert database.execute("SELECT count(*) FROM docs WHERE docs MATCH 'erm'").fetchone()[0] == 1
    profile = get_provider_profile("openai-codex")
    assert profile.api_mode == "codex_responses" and profile.auth_type == "oauth_external"
    assert APIServerAdapter is not None and AIAgent is not None
    assert os.getuid() == 10000 and os.environ["HERMES_HOME"] == "/opt/data"
    assert not Path("/opt/data/auth.json").exists()
    print("Native Hermes API image smoke passed; no authentication or inference performed.")


if __name__ == "__main__":
    main()
