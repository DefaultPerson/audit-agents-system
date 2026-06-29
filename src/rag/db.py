"""
LanceDB vector database for exploit documents.
"""

from typing import Any

import lancedb

from ..config import RAGConfig

_db: lancedb.DBConnection | None = None
_table: lancedb.table.Table | None = None


async def init_db() -> lancedb.DBConnection:
    """Initialize LanceDB connection."""
    global _db

    if _db is not None:
        return _db

    # Ensure directory exists
    db_path = RAGConfig.lancedb_path.parent
    db_path.mkdir(parents=True, exist_ok=True)

    _db = lancedb.connect(str(db_path))
    return _db


async def get_table() -> lancedb.table.Table:
    """Get or create the exploits table."""
    global _table

    if _table is not None:
        return _table

    db = await init_db()
    table_names = db.table_names()

    if "exploits" in table_names:
        _table = db.open_table("exploits")
    else:
        # Create table with initial dummy data
        initial_data = [
            {
                "id": "_init",
                "name": "",
                "date": "",
                "chain": "",
                "loss_usd": 0.0,
                "attack_type": "",
                "root_cause": "",
                "summary": "",
                "attack_flow": "",
                "poc_code": "",
                "file_path": "",
                "vector": [0.0] * RAGConfig.embedding_dims,
            }
        ]
        _table = db.create_table("exploits", initial_data)

    return _table


async def insert_documents(
    documents: list[dict[str, Any]], embeddings: list[list[float]]
) -> None:
    """Insert documents with embeddings."""
    if len(documents) != len(embeddings):
        raise ValueError("Documents and embeddings count mismatch")

    table = await get_table()

    records = [
        {
            "id": doc["id"],
            "name": doc["name"],
            "date": doc["date"],
            "chain": doc["chain"],
            "loss_usd": doc.get("loss_usd") or doc.get("lossUsd") or 0.0,
            "attack_type": doc.get("attack_type") or doc.get("attackType") or "",
            "root_cause": doc.get("root_cause") or doc.get("rootCause") or "",
            "summary": doc["summary"],
            "attack_flow": doc.get("attack_flow") or doc.get("attackFlow") or "",
            "poc_code": doc.get("poc_code") or doc.get("pocCode") or "",
            "file_path": doc.get("file_path") or doc.get("filePath") or "",
            "vector": embeddings[i],
        }
        for i, doc in enumerate(documents)
    ]

    table.add(records)
    print(f"Inserted {len(records)} documents")


async def create_fts_index() -> None:
    """Create full-text search indexes."""
    table = await get_table()

    try:
        table.create_fts_index("summary")
        table.create_fts_index("attack_flow")
        table.create_fts_index("root_cause")
        print("FTS indexes created")
    except Exception as e:
        if "already exists" not in str(e).lower():
            raise


async def get_document_count() -> int:
    """Get document count."""
    table = await get_table()
    return table.count_rows()


async def is_initialized() -> bool:
    """Check if database is initialized with documents."""
    try:
        count = await get_document_count()
        return count > 1  # More than just the init document
    except Exception:
        return False


async def clear_documents() -> None:
    """Clear all documents."""
    global _table

    db = await init_db()
    table_names = db.table_names()

    if "exploits" in table_names:
        db.drop_table("exploits")
        _table = None
        print("Table cleared")


def close_db() -> None:
    """Close database connection."""
    global _db, _table
    _db = None
    _table = None


async def init_lancedb() -> None:
    """Initialize the LanceDB database."""
    await init_db()
    await get_table()
    print("LanceDB initialized")


async def ingest_exploits(exploits: list) -> int:
    """Ingest parsed exploits into the database."""
    from .embeddings import embed_batch
    from .parser import to_document_dict

    if not exploits:
        return 0

    # Convert to document dicts
    documents = [to_document_dict(e) for e in exploits]

    # Generate embeddings
    texts = [
        f"{doc['name']} {doc['attack_type']} {doc['root_cause']} {doc['summary']}"
        for doc in documents
    ]
    embeddings = await embed_batch(texts)

    # Insert into database
    await insert_documents(documents, embeddings)

    # Create FTS index
    await create_fts_index()

    return len(documents)
