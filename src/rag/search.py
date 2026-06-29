"""
Hybrid search: semantic (vector) + keyword (BM25) with RRF reranking.
"""

from dataclasses import dataclass
from typing import Any

from ..config import RAGConfig
from ..models import ExploitDocument
from .db import get_table
from .embeddings import embed_query


@dataclass
class SearchResult:
    """Search result with score and match type."""

    id: str
    name: str
    date: str
    chain: str
    loss_usd: float | None
    attack_type: str
    root_cause: str
    summary: str
    attack_flow: str
    poc_code: str
    file_path: str
    score: float
    match_type: str  # "semantic" | "keyword" | "hybrid"

    def to_exploit_document(self) -> ExploitDocument:
        """Convert to ExploitDocument model."""
        return ExploitDocument(
            id=self.id,
            name=self.name,
            date=self.date,
            chain=self.chain,
            lossUsd=self.loss_usd,
            attackType=self.attack_type,
            rootCause=self.root_cause,
            summary=self.summary,
            attackFlow=self.attack_flow,
            pocCode=self.poc_code,
            filePath=self.file_path,
        )


def _row_to_result(row: Any, score: float, match_type: str) -> SearchResult:
    """Convert LanceDB row to SearchResult."""
    return SearchResult(
        id=row.get("id", ""),
        name=row.get("name", ""),
        date=row.get("date", ""),
        chain=row.get("chain", ""),
        loss_usd=row.get("loss_usd") or row.get("lossUsd"),
        attack_type=row.get("attack_type") or row.get("attackType") or "",
        root_cause=row.get("root_cause") or row.get("rootCause") or "",
        summary=row.get("summary", ""),
        attack_flow=row.get("attack_flow") or row.get("attackFlow") or "",
        poc_code=row.get("poc_code") or row.get("pocCode") or "",
        file_path=row.get("file_path") or row.get("filePath") or "",
        score=score,
        match_type=match_type,
    )


async def semantic_search(
    query_vector: list[float], limit: int | None = None
) -> list[SearchResult]:
    """Semantic search using vector similarity."""
    limit = limit or RAGConfig.top_k
    table = await get_table()

    # Request extra results to account for filtering _init record
    results = table.search(query_vector).limit(limit + 1).to_list()

    return [
        _row_to_result(
            r,
            score=1 / (1 + r.get("_distance", 0)) if r.get("_distance") else 1.0,
            match_type="semantic",
        )
        for r in results
        if r.get("id") != "_init"  # Filter out init record
    ][:limit]


async def keyword_search(query: str, limit: int | None = None) -> list[SearchResult]:
    """Keyword search using full-text search."""
    limit = limit or RAGConfig.top_k
    table = await get_table()

    try:
        # Request extra results to account for filtering _init record
        results = table.search(query, query_type="fts").limit(limit + 1).to_list()

        return [
            _row_to_result(
                r,
                score=r.get("_score", 1.0),
                match_type="keyword",
            )
            for r in results
            if r.get("id") != "_init"  # Filter out init record
        ][:limit]
    except Exception as e:
        # FTS index might not exist
        print(f"Warning: Keyword search failed: {e}")
        return []


def rrf_rerank(
    semantic_results: list[SearchResult],
    keyword_results: list[SearchResult],
    semantic_weight: float | None = None,
    keyword_weight: float | None = None,
    k: int = 60,
) -> list[SearchResult]:
    """
    Reciprocal Rank Fusion (RRF) for combining results.

    RRF score = sum(1 / (k + rank)) where k = 60 (standard)
    """
    semantic_weight = semantic_weight or RAGConfig.semantic_weight
    keyword_weight = keyword_weight or RAGConfig.keyword_weight

    scores: dict[str, tuple[float, SearchResult]] = {}

    # Add semantic results with weighted RRF
    for rank, result in enumerate(semantic_results):
        rrf_score = semantic_weight * (1 / (k + rank + 1))
        if result.id in scores:
            scores[result.id] = (scores[result.id][0] + rrf_score, result)
        else:
            scores[result.id] = (rrf_score, result)

    # Add keyword results with weighted RRF
    for rank, result in enumerate(keyword_results):
        rrf_score = keyword_weight * (1 / (k + rank + 1))
        if result.id in scores:
            scores[result.id] = (scores[result.id][0] + rrf_score, scores[result.id][1])
        else:
            result.match_type = "keyword"
            scores[result.id] = (rrf_score, result)

    # Sort by combined score and update match_type to hybrid
    sorted_results = sorted(scores.values(), key=lambda x: x[0], reverse=True)

    return [
        SearchResult(
            id=r.id,
            name=r.name,
            date=r.date,
            chain=r.chain,
            loss_usd=r.loss_usd,
            attack_type=r.attack_type,
            root_cause=r.root_cause,
            summary=r.summary,
            attack_flow=r.attack_flow,
            poc_code=r.poc_code,
            file_path=r.file_path,
            score=score,
            match_type="hybrid",
        )
        for score, r in sorted_results
    ]


async def hybrid_search(query: str, limit: int | None = None) -> list[SearchResult]:
    """
    Hybrid search combining semantic and keyword search with RRF reranking.
    """
    limit = limit or RAGConfig.top_k

    # Get query embedding
    query_vector = await embed_query(query)

    # Run both searches in parallel
    import asyncio

    semantic_results, keyword_results = await asyncio.gather(
        semantic_search(query_vector, limit * 2),
        keyword_search(query, limit * 2),
    )

    # Combine with RRF reranking
    combined = rrf_rerank(semantic_results, keyword_results)

    return combined[:limit]


async def search_by_attack_type(
    attack_type: str, limit: int = 10
) -> list[SearchResult]:
    """Search by attack type."""
    table = await get_table()

    # Use SQL-style filter
    results = (
        table.search()
        .where(f"attack_type = '{attack_type}'", prefilter=True)
        .limit(limit)
        .to_list()
    )

    return [_row_to_result(r, score=1.0, match_type="keyword") for r in results]


async def search_by_chain(chain: str, limit: int = 10) -> list[SearchResult]:
    """Search by chain."""
    table = await get_table()

    results = (
        table.search()
        .where(f"chain = '{chain}'", prefilter=True)
        .limit(limit)
        .to_list()
    )

    return [_row_to_result(r, score=1.0, match_type="keyword") for r in results]


def format_search_results(results: list[SearchResult]) -> str:
    """Format search results for display."""
    if not results:
        return "No results found."

    lines = []
    for i, r in enumerate(results):
        loss = f"${r.loss_usd / 1_000_000:.2f}M" if r.loss_usd else "Unknown"
        lines.append(
            f"\n{i + 1}. {r.name} ({r.date})\n"
            f"   Chain: {r.chain} | Loss: {loss} | Type: {r.attack_type}\n"
            f"   Score: {r.score:.4f} ({r.match_type})\n"
            f"   {r.summary[:200]}..."
        )

    return "\n".join(lines)
