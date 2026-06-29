"""
Configuration management using pydantic-settings.
Migrated from backend/src/config.ts.
"""

from pathlib import Path
from typing import ClassVar

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import ChainConfig


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # RPC endpoints
    eth_rpc_url: str = Field(
        default="https://eth.llamarpc.com",
        alias="ETH_RPC_URL",
    )
    bsc_rpc_url: str = Field(
        default="https://lb.drpc.org/ogrpc?network=bsc",
        alias="BSC_RPC_URL",
    )
    base_rpc_url: str = Field(
        default="https://mainnet.base.org",
        alias="BASE_RPC_URL",
    )
    polygon_rpc_url: str = Field(
        default="https://polygon-rpc.com",
        alias="POLYGON_RPC_URL",
    )
    arbitrum_rpc_url: str = Field(
        default="https://arb1.arbitrum.io/rpc",
        alias="ARBITRUM_RPC_URL",
    )

    # Explorer API keys
    etherscan_api_key: str | None = Field(default=None, alias="ETHERSCAN_API_KEY")
    bscscan_api_key: str | None = Field(default=None, alias="BSCSCAN_API_KEY")
    basescan_api_key: str | None = Field(default=None, alias="BASESCAN_API_KEY")
    polygonscan_api_key: str | None = Field(default=None, alias="POLYGONSCAN_API_KEY")
    arbiscan_api_key: str | None = Field(default=None, alias="ARBISCAN_API_KEY")

    # Voyage AI for embeddings
    voyage_api_key: str | None = Field(default=None, alias="VOYAGE_API_KEY")
    voyage_paid: bool = Field(default=False, alias="VOYAGE_PAID")

    # Decompilation
    dedaub_api_key: str | None = Field(default=None, alias="DEDAUB_API_KEY")
    dedaub_cookies: str | None = Field(default=None, alias="DEDAUB_COOKIES")
    dedaub_poll_attempts: int = Field(default=120, alias="DEDAUB_POLL_ATTEMPTS")
    dedaub_poll_interval_seconds: float = Field(
        default=2.0,
        alias="DEDAUB_POLL_INTERVAL_SECONDS",
    )

    # Telegram notifications
    telegram_bot_token: str | None = Field(default=None, alias="TELEGRAM_BOT_TOKEN")
    telegram_chat_id: str | None = Field(default=None, alias="TELEGRAM_CHAT_ID")

    # Local node RPC (for Rust extractor)
    erigon_rpc_url: str | None = Field(default=None, alias="ERIGON_RPC_URL")

    # Claude Code authentication (all optional - uses system credentials by default)
    # Priority: ANTHROPIC_API_KEY > CLAUDE_CODE_OAUTH_TOKEN > system login
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    claude_oauth_token: str | None = Field(default=None, alias="CLAUDE_CODE_OAUTH_TOKEN")

    # HTTP Proxies for external API calls (comma-separated URLs)
    # Format: http://user:pass@ip:port or http://ip:port
    http_proxies: str | None = Field(default=None, alias="HTTP_PROXIES")

    def get_proxy_list(self) -> list[str]:
        """Parse HTTP_PROXIES into a list of proxy URLs."""
        if not self.http_proxies:
            return []
        return [p.strip() for p in self.http_proxies.split(",") if p.strip()]


# Singleton settings instance
settings = Settings()


class AuditConfig:
    """Audit configuration constants."""

    # Target criteria
    min_balance_usd: ClassVar[int] = 100_000
    min_age_days: ClassVar[int] = 730  # 2 years

    # Rate limiting
    rpc_rate_limit: ClassVar[int] = 5  # requests per second
    explorer_rate_limit: ClassVar[int] = 5  # requests per second

    # Retrieval
    rag_top_k: ClassVar[int] = 5

    # Paths
    data_dir: ClassVar[Path] = Path("./data")
    db_path: ClassVar[Path] = Path("./data/targets.db")
    pipeline_log_path: ClassVar[Path] = Path("./data/pipeline.log")
    rag_dir: ClassVar[Path] = Path("./data/rag")
    audits_dir: ClassVar[Path] = Path("./audits")

    # ============================================
    # Parallel Audit Prompt Configuration
    # ============================================
    # Format: {prompt_file_path: instance_count}
    # Total instances = sum of all counts
    audit_prompts: ClassVar[dict[str, int]] = {
        "prompts/anchored.md": 1,  # 1 instances with checklist + few-shot
        "prompts/open.md": 1,  # 1 instance with fresh eyes + CoT
    }

    # Critic phase is disabled until prompts/critic.md is intentionally restored.
    # The evidence-gated autoresearch path should be preferred for new work.
    enable_critic_phase: ClassVar[bool] = False
    critic_prompt_path: ClassVar[str] = "prompts/critic.md"
    critic_min_score: ClassVar[int] = 12  # Findings below this are filtered

    # Timeout per audit instance (ms)
    audit_timeout_ms: ClassVar[int] = 1200000  # 20 min

    # Max retries per failed instance
    audit_max_retries: ClassVar[int] = 3

    # Two-stage audit: follow-up for Solidity < 0.8.0
    enable_arithmetic_followup: ClassVar[bool] = True


class RAGConfig:
    """RAG configuration constants."""

    embedding_model: ClassVar[str] = "voyage-code-3"
    embedding_dims: ClassVar[int] = 1024
    chunk_size: ClassVar[int] = 1024
    chunk_overlap: ClassVar[int] = 50
    chunking_method: ClassVar[str] = "ast"
    retrieval_strategy: ClassVar[str] = "hybrid"
    semantic_weight: ClassVar[float] = 0.65
    keyword_weight: ClassVar[float] = 0.35
    reranker: ClassVar[str] = "rrf"
    top_k: ClassVar[int] = 5
    lancedb_path: ClassVar[Path] = Path("./data/rag/exploits.lance")
    defihacklabs_path: ClassVar[Path] = Path("./data/DeFiHackLabs")


class TelegramConfig:
    """Telegram configuration."""

    bot_token: ClassVar[str | None] = settings.telegram_bot_token
    chat_id: ClassVar[str | None] = settings.telegram_chat_id
    retry_attempts: ClassVar[int] = 3
    retry_delay_ms: ClassVar[int] = 1000
    # File storage for pending PoC requests (shared between pipeline and bot)
    pending_poc_file: ClassVar[Path] = Path("./data/pending_poc.json")


class DedaubConfig:
    """Dedaub API configuration."""

    api_key: ClassVar[str | None] = settings.dedaub_api_key
    base_url: ClassVar[str] = "https://api.dedaub.com"
    timeout: ClassVar[int] = 60000


class SignatureDB:
    """Signature database URLs."""

    primary: ClassVar[str] = "https://api.4byte.sourcify.dev/api/v1/signatures"
    fallback: ClassVar[str] = "https://api.etherface.io/v1/signatures/hash/all"


class DiscoveryConfig:
    """Discovery configuration for finding contracts."""

    # Target criteria
    min_balance_usd: ClassVar[int] = 100_000
    default_limit: ClassVar[int] = 10_000

    # Rate limiting
    scrape_rate_limit: ClassVar[float] = 1.0  # seconds between requests
    error_backoff: ClassVar[float] = 5.0  # seconds to wait after error

    # Target chains for discovery
    target_chains: ClassVar[list[str]] = ["eth", "bsc", "arbitrum", "base", "polygon"]

    # Rust extractor path (relative to project root)
    rust_extractor_path: ClassVar[str] = "../snapshot-extractor"


class PriceConfig:
    """DeFiLlama price service configuration."""

    # API endpoint
    defillama_base_url: ClassVar[str] = "https://coins.llama.fi"

    # Cache TTL
    cache_ttl_seconds: ClassVar[int] = 60

    # Request timeout
    timeout_seconds: ClassVar[int] = 10

    # Fallback prices when API unavailable
    fallback_prices: ClassVar[dict[str, float]] = {
        "eth": 3500.0,
        "bsc": 600.0,
        "arbitrum": 3500.0,
        "base": 3500.0,
        "polygon": 0.5,
        "avalanche": 35.0,
        "optimism": 3500.0,
        "fantom": 0.5,
        "gnosis": 1.0,
    }


def get_chain_config(chain: str) -> ChainConfig:
    """Get chain configuration by chain ID."""
    return CHAINS[chain]


def get_audit_dir(chain: str, address: str) -> Path:
    """Get the audit output directory for a specific contract."""
    return AuditConfig.audits_dir / f"{chain}_{address.lower()}"


# Chain configurations
CHAINS: dict[str, ChainConfig] = {
    "eth": ChainConfig(
        name="Ethereum",
        chainId=1,
        rpcUrl=settings.eth_rpc_url,
        explorerUrl="https://etherscan.io",
        explorerApiUrl="https://api.etherscan.io/v2/api",
        explorerApiKey=settings.etherscan_api_key,
        nativeCurrency="ETH",
        nativeDecimals=18,
    ),
    "bsc": ChainConfig(
        name="BNB Smart Chain",
        chainId=56,
        rpcUrl=settings.bsc_rpc_url,
        explorerUrl="https://bscscan.com",
        explorerApiUrl="https://api.bscscan.com/v2/api",
        explorerApiKey=settings.bscscan_api_key,
        nativeCurrency="BNB",
        nativeDecimals=18,
    ),
    "base": ChainConfig(
        name="Base",
        chainId=8453,
        rpcUrl=settings.base_rpc_url,
        explorerUrl="https://basescan.org",
        explorerApiUrl="https://api.etherscan.io/v2/api",
        explorerApiKey=settings.basescan_api_key,
        nativeCurrency="ETH",
        nativeDecimals=18,
    ),
    "polygon": ChainConfig(
        name="Polygon",
        chainId=137,
        rpcUrl=settings.polygon_rpc_url,
        explorerUrl="https://polygonscan.com",
        explorerApiUrl="https://api.etherscan.io/v2/api",
        explorerApiKey=settings.polygonscan_api_key,
        nativeCurrency="POL",
        nativeDecimals=18,
    ),
    "arbitrum": ChainConfig(
        name="Arbitrum One",
        chainId=42161,
        rpcUrl=settings.arbitrum_rpc_url,
        explorerUrl="https://arbiscan.io",
        explorerApiUrl="https://api.etherscan.io/v2/api",
        explorerApiKey=settings.arbiscan_api_key,
        nativeCurrency="ETH",
        nativeDecimals=18,
    ),
}
