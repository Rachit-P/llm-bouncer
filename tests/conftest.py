import pytest

from llm_bouncer import policy


@pytest.fixture(autouse=True)
def _private_home(tmp_path, monkeypatch):
    """Keep every test away from the real ~/.llm-bouncer (ledgers and personal policy)."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LLM_BOUNCER_DIR", str(tmp_path / "ledger"))
    for k in ("LLM_BOUNCER_POLICY", "LLM_BOUNCER_MODE", "LLM_BOUNCER_FAIL_OPEN", "LLM_BOUNCER_RETENTION_DAYS",
              "LLM_BOUNCER_GATE", "LLM_BOUNCER_UPSTREAM_PROXY", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(k, raising=False)
    policy._load.cache_clear()
    yield
    policy._load.cache_clear()
