"""Exercise the NoneCRM profile through Hermes' existing provider/tool resolvers."""
from pathlib import Path

import yaml

from hermes_cli.tools_config import _get_platform_tools
from providers import get_provider_profile
from toolsets import resolve_toolset


def load_profile():
    return yaml.safe_load(
        (Path(__file__).parents[2] / "ops/nonecrm/config.example.yaml").read_text()
    )


def test_primary_uses_native_codex_responses_not_app_server():
    config = load_profile()
    profile = get_provider_profile(config["model"]["provider"])
    assert profile.api_mode == "codex_responses"
    assert profile.auth_type == "oauth_external"
    assert config["model"]["default"] == "gpt-6-luna"
    assert config["model"]["openai_runtime"] == "auto"


def test_openrouter_fallback_is_separate_from_oauth_primary():
    config = load_profile()
    assert config["fallback_providers"] == [
        {"provider": "openrouter", "model": "openai/gpt-6-luna"}
    ]
    assert get_provider_profile("openrouter").api_mode != "codex_responses"


def test_native_api_tool_selection_does_not_enable_host_actions():
    config = load_profile()
    enabled = _get_platform_tools(config, "api_server")
    assert enabled == {"skills", "todo"}
    tools = {tool for toolset in enabled for tool in resolve_toolset(toolset)}
    assert tools
    assert not tools.intersection({
        "terminal", "process", "execute_code", "read_file", "write_file",
        "patch", "delegate_task", "cronjob", "send_message",
    })


def test_api_settings_preserve_existing_crm_contract():
    api = load_profile()["gateway"]["api_server"]
    assert api["enabled"] is True
    assert api["port"] == 8642
    assert api["model_name"] == "hermes-agent"
    assert api["max_concurrent_runs"] == 1
    assert "key" not in api  # Runtime secret, never shipped in the profile.
