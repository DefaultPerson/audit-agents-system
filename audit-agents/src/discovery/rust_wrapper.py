"""
Wrapper for Rust snapshot-extractor binary.
Requires ERIGON_RPC_URL environment variable for local Erigon/Geth node.
"""

import asyncio
import logging
import os
import sqlite3
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from ..models import Chain, ContractStatus, ContractTarget

logger = logging.getLogger(__name__)

# Path to Rust binary relative to project root
RUST_BINARY = Path(__file__).parent.parent.parent.parent / "snapshot-extractor" / "target" / "release" / "snapshot-extractor"


class RustExtractor:
    """
    Wrapper around Rust snapshot-extractor binary.

    The Rust extractor uses debug_accountRange RPC to iterate all accounts
    and find high-balance contracts. Requires local Erigon node.
    """

    def __init__(self, binary_path: Path | None = None):
        """
        Initialize extractor.

        Args:
            binary_path: Path to Rust binary (auto-detected if None)
        """
        self._binary_path = binary_path or RUST_BINARY

    def is_available(self) -> bool:
        """Check if Rust extractor binary is available."""
        return self._binary_path.exists()

    def build(self) -> bool:
        """
        Build Rust extractor if not available.

        Returns:
            True if build succeeded
        """
        cargo_dir = self._binary_path.parent.parent.parent
        cargo_toml = cargo_dir / "Cargo.toml"

        if not cargo_toml.exists():
            logger.error("Cargo.toml not found at %s", cargo_dir)
            return False

        logger.info("Building Rust extractor...")
        try:
            import subprocess

            result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=cargo_dir,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes
            )

            if result.returncode != 0:
                logger.error("Build failed: %s", result.stderr)
                return False

            logger.info("Build complete!")
            return True

        except Exception as e:
            logger.error("Build error: %s", e)
            return False

    async def extract(
        self,
        chain: str,
        min_balance_usd: float = 100_000,
        rpc_url: str | None = None,
        snapshot_block: int | None = None,
    ) -> tuple[list[ContractTarget], list[str]]:
        """
        Run Rust extractor to find high-balance contracts.

        Args:
            chain: Chain ID (e.g., "eth", "bsc")
            min_balance_usd: Minimum balance threshold in USD
            rpc_url: RPC URL (uses ERIGON_RPC_URL env if None)
            snapshot_block: Optional pinned block for debug_accountRange

        Returns:
            Tuple of (contracts list, errors list)
        """
        errors: list[str] = []

        # Check binary
        if not self.is_available():
            logger.warning("Rust extractor not built, attempting build...")
            if not self.build():
                return [], ["Rust extractor not available and build failed"]

        # Get RPC URL
        rpc = rpc_url or os.environ.get("ERIGON_RPC_URL")
        if not rpc:
            return [], ["ERIGON_RPC_URL not set. Rust extractor requires local Erigon/Geth node with debug API."]

        # Create temp SQLite file for output
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            output_path = tmp.name

        try:
            # Run extractor
            logger.info("Running Rust extractor for %s...", chain)

            command = self._build_command(
                chain=chain,
                rpc=rpc,
                min_balance_usd=min_balance_usd,
                output_path=output_path,
                snapshot_block=snapshot_block,
            )
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=1800,  # 30 minutes
            )

            if process.returncode != 0:
                error = stderr.decode() if stderr else "Unknown error"
                return [], [f"Extractor failed: {error}"]

            # Parse results from SQLite
            contracts = self._parse_output(output_path, chain)
            logger.info("Extracted %d contracts", len(contracts))

            return contracts, errors

        except TimeoutError:
            return [], ["Extraction timed out (30 minutes)"]
        except Exception as e:
            return [], [f"Extraction error: {e}"]
        finally:
            # Cleanup temp file
            with suppress(OSError):
                os.unlink(output_path)

    def _build_command(
        self,
        *,
        chain: str,
        rpc: str,
        min_balance_usd: float,
        output_path: str,
        snapshot_block: int | None = None,
    ) -> list[str]:
        """Build snapshot-extractor command."""
        command = [
            str(self._binary_path),
            "--chain",
            chain,
            "--rpc",
            rpc,
            "--min-balance",
            str(int(min_balance_usd)),
            "--output",
            output_path,
        ]
        if snapshot_block is not None:
            command.extend(["--block", str(snapshot_block)])
        return command

    def _parse_output(self, db_path: str, chain: str) -> list[ContractTarget]:
        """
        Parse contracts from Rust extractor SQLite output.

        Args:
            db_path: Path to SQLite database
            chain: Chain ID

        Returns:
            List of ContractTarget
        """
        contracts: list[ContractTarget] = []
        chain_enum = Chain(chain.lower())

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT address, balance_usd, balance_native, age, verified, status, code_hash, found_at
                FROM contracts
                WHERE chain = ?
            """, (chain,))

            for row in cursor.fetchall():
                address, balance_usd, balance_native, age, verified, status, code_hash, found_at = row

                contract = ContractTarget(
                    address=address.lower(),
                    chain=chain_enum,
                    balanceUsd=balance_usd or 0.0,
                    balanceNative=balance_native or "0",
                    age=age or 0,
                    verified=bool(verified),
                    status=ContractStatus(status) if status else ContractStatus.NEW,
                    codeHash=code_hash,
                    foundAt=datetime.fromisoformat(found_at) if found_at else datetime.now(UTC),
                )
                contracts.append(contract)

            conn.close()

        except Exception as e:
            logger.error("Error parsing output: %s", e)

        return contracts
