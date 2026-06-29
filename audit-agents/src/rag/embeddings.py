"""
Voyage AI embeddings for code similarity search.
"""

import asyncio

import httpx

from ..config import RAGConfig, settings

_voyage_api_key: str | None = None


def init_embeddings(api_key: str | None = None) -> None:
    """Initialize embeddings with API key."""
    global _voyage_api_key
    _voyage_api_key = api_key or settings.voyage_api_key
    if not _voyage_api_key:
        print("Warning: VOYAGE_API_KEY not set - embeddings will fail")


async def embed_code(text: str) -> list[float]:
    """Generate embeddings for code text using Voyage AI."""
    api_key = _voyage_api_key or settings.voyage_api_key
    if not api_key:
        raise ValueError("VOYAGE_API_KEY not configured")

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.voyageai.com/v1/embeddings",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            json={
                "input": text,
                "model": RAGConfig.embedding_model,
                "input_type": "document",
                "output_dimension": RAGConfig.embedding_dims,
            },
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Voyage API error: {response.status_code} - {response.text}"
            )

        data = response.json()
        if not data.get("data") or not data["data"][0].get("embedding"):
            raise RuntimeError("Invalid response from Voyage API")

        return data["data"][0]["embedding"]


async def embed_query(query: str) -> list[float]:
    """Generate embeddings for a search query."""
    api_key = _voyage_api_key or settings.voyage_api_key
    if not api_key:
        raise ValueError("VOYAGE_API_KEY not configured")

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.voyageai.com/v1/embeddings",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            json={
                "input": query,
                "model": RAGConfig.embedding_model,
                "input_type": "query",
                "output_dimension": RAGConfig.embedding_dims,
            },
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Voyage API error: {response.status_code} - {response.text}"
            )

        data = response.json()
        if not data.get("data") or not data["data"][0].get("embedding"):
            raise RuntimeError("Invalid response from Voyage API")

        return data["data"][0]["embedding"]


async def embed_batch(texts: list[str]) -> list[list[float]]:
    """Batch embed multiple texts (more efficient)."""
    api_key = _voyage_api_key or settings.voyage_api_key
    if not api_key:
        raise ValueError("VOYAGE_API_KEY not configured")

    # Voyage AI supports up to 128 inputs per batch
    # Free tier: 10K TPM, so use smaller batches
    is_paid = settings.voyage_paid
    batch_size = 128 if is_paid else 8

    results: list[list[float]] = []

    async with httpx.AsyncClient(timeout=120) as client:
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            retries = 0
            max_retries = 5

            while retries < max_retries:
                response = await client.post(
                    "https://api.voyageai.com/v1/embeddings",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                    json={
                        "input": batch,
                        "model": RAGConfig.embedding_model,
                        "input_type": "document",
                        "output_dimension": RAGConfig.embedding_dims,
                    },
                )

                if response.status_code == 429:
                    retries += 1
                    wait_time = min(60, 10 * (2**retries))
                    print(
                        f"  Rate limited, waiting {wait_time}s (retry {retries}/{max_retries})..."
                    )
                    await asyncio.sleep(wait_time)
                    continue

                if response.status_code != 200:
                    raise RuntimeError(
                        f"Voyage API error: {response.status_code} - {response.text}"
                    )

                data = response.json()
                results.extend(d["embedding"] for d in data["data"])
                break

            if retries >= max_retries:
                raise RuntimeError(
                    f"Voyage API rate limit exceeded after {max_retries} retries"
                )

            # Rate limiting delay
            delay_ms = 200 if is_paid else 21000  # 3 RPM for free tier
            if i + batch_size < len(texts):
                remaining = (len(texts) - i - batch_size) // batch_size + 1
                eta = (remaining * delay_ms) // 60000
                print(
                    f"  Batch {i // batch_size + 1}/{(len(texts) - 1) // batch_size + 1} done. ETA: ~{eta} min"
                )
                await asyncio.sleep(delay_ms / 1000)

    return results
