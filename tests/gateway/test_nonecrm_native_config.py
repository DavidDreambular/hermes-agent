"""Verify owner deployment configuration through existing native resolvers."""
from pathlib import Path

import yaml

from hermes_cli.tools_config import _get_platform_tools
from providers import get_provider_profile
from toolsets import resolve_toolset


def load_profile():
    return yaml.safe_load((Path(__file__).parents[2] / "ops/nonecrm/config.example.yaml").read_text(encoding="utf-8"))


def test_primary_uses_native_codex_responses_not_app_server():
    config = load_profile()
    profile = get_provider_profile(config["model"]["provider"])
    assert profile.api_mode == "codex_responses" and profile.auth_type == "oauth_external"
    assert config["model"]["default"] == "gpt-6-luna"
    assert config["model"]["openai_runtime"] == "auto"


def test_fallback_remains_separate_from_native_oauth():
    assert load_profile()["fallback_providers"] == [{"provider": "openrouter", "model": "openai/gpt-6-luna"}]
    assert get_provider_profile("openrouter").api_mode != "codex_responses"


def test_effective_tools_do_not_include_host_actions():
    enabled = _get_platform_tools(load_profile(), "api_server")
    assert enabled == {"skills", "todo"}
    tools = {tool for toolset in enabled for tool in resolve_toolset(toolset)}
    assert tools and not tools.intersection({"terminal", "process", "execute_code", "read_file", "write_file", "patch", "delegate_task", "cronjob", "send_message"})


def test_existing_crm_api_contract_is_preserved():
    api = load_profile()["gateway"]["api_server"]
    assert api["enabled"] is True and api["port"] == 8642
    assert api["model_name"] == "hermes-agent" and api["max_concurrent_runs"] == 1
    assert "key" not in api
