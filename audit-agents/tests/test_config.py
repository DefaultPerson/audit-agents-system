"""Tests for chain configuration."""

from cli.main import _mask_rpc_url
from src.config import CHAINS, DiscoveryConfig, get_chain_config
from src.models import Chain


def test_all_chain_enum_values_have_config() -> None:
    assert {chain.value for chain in Chain} == set(CHAINS)


def test_discovery_target_chains_are_configured() -> None:
    for chain in DiscoveryConfig.target_chains:
        config = get_chain_config(chain)
        assert config.chain_id > 0
        assert config.rpc_url.startswith("http")


def test_mask_rpc_url_redacts_userinfo_and_query() -> None:
    masked = _mask_rpc_url("https://user:secret@example.test/rpc?api_key=secret")

    assert "secret" not in masked
    assert "<redacted>" in masked
