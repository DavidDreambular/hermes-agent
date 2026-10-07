"""Execute fixed service entrypoint rejection, not source-text assertions."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.linux_only
@pytest.mark.parametrize("values", [{}, {"SERVICE": "another-client", "ENVIRONMENT": "production"},
                                    {"SERVICE": "nonecrm-hermes-agent", "ENVIRONMENT": "staging"}])
def test_fixed_recovery_rejects_undelegated_invocation(values):
    program = Path(__file__).parents[2] / "ops/production-guard/nonecrm-hermes-agent-deploy"
    result = subprocess.run(["/bin/bash", str(program)], env={"PATH": "/usr/bin:/bin", **values},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 1
    assert "failed closed" in result.stdout
    assert not result.stderr
    assert "API_KEY" not in result.stdout
