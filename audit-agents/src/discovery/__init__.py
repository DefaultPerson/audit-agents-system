"""
Discovery module for finding high-value smart contracts.

Supports two modes:
- Light mode: HTML scraping from block explorers (no node required)
- Full mode: Rust extractor with local Erigon node (complete state)
"""

from .light_mode import LightModeScanner
from .orchestrator import DiscoveryCriteria, DiscoveryOrchestrator
from .rust_wrapper import RustExtractor

__all__ = [
    "DiscoveryCriteria",
    "DiscoveryOrchestrator",
    "LightModeScanner",
    "RustExtractor",
]
