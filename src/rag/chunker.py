"""
AST-aware code chunking for Solidity.

Falls back to regex-based chunking if tree-sitter is not available.
"""

import re
from dataclasses import dataclass
from typing import Literal

from ..config import RAGConfig


@dataclass
class CodeChunk:
    """A chunk of code for embedding."""

    content: str
    type: Literal["contract", "function", "state", "import", "comment", "text"]
    start_line: int | None = None
    end_line: int | None = None
    name: str | None = None


# Approximate tokens per character for Solidity code
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Estimate token count for text."""
    return (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN


def chunk_by_tokens(code: str, max_tokens: int, overlap: int) -> list[CodeChunk]:
    """Simple token-based chunking (fallback)."""
    chunks: list[CodeChunk] = []
    max_chars = max_tokens * CHARS_PER_TOKEN
    overlap_chars = overlap * CHARS_PER_TOKEN

    start = 0
    while start < len(code):
        end = min(start + max_chars, len(code))

        # Try to break at line boundary
        if end < len(code):
            line_break = code.rfind("\n", start, end)
            if line_break > start + max_chars // 2:
                end = line_break + 1

        chunks.append(CodeChunk(content=code[start:end], type="text"))

        start = end - overlap_chars
        if start >= len(code) - overlap_chars:
            break

    return chunks


def chunk_solidity_regex(code: str, max_tokens: int) -> list[CodeChunk]:
    """Regex-based Solidity chunking (better than pure token-based)."""
    chunks: list[CodeChunk] = []

    # Extract imports and pragmas as separate chunk
    header_match = re.match(
        r"^((?://.*\n|/\*[\s\S]*?\*/|\s*pragma[^;]+;|\s*import[^;]+;|\s*\n)*)",
        code,
    )
    if header_match and header_match.group(1) and header_match.group(1).strip():
        chunks.append(CodeChunk(content=header_match.group(1), type="import", name="header"))

    # Find all contract definitions
    contract_pattern = re.compile(r"(?:contract|interface|library)\s+(\w+)[^{]*\{")

    contracts: list[tuple[str, int, int]] = []
    for match in contract_pattern.finditer(code):
        start_idx = match.start()
        brace_count = 0
        end_idx = start_idx

        # Find matching closing brace
        brace_start = code.find("{", start_idx)
        for i in range(brace_start, len(code)):
            if code[i] == "{":
                brace_count += 1
            elif code[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break

        contracts.append((match.group(1), start_idx, end_idx))

    # Process each contract
    for name, start, end in contracts:
        contract_code = code[start:end]
        contract_tokens = estimate_tokens(contract_code)

        if contract_tokens <= max_tokens:
            # Contract fits in one chunk
            chunks.append(CodeChunk(content=contract_code, type="contract", name=name))
        else:
            # Split contract into functions
            function_pattern = re.compile(r"function\s+(\w+)\s*\([^)]*\)[^{]*\{")

            # Extract state variables (before first function)
            first_func = re.search(r"function\s+\w+", contract_code)
            if first_func and first_func.start() > 0:
                state_vars = contract_code[: first_func.start()]
                if state_vars.strip():
                    chunks.append(
                        CodeChunk(
                            content=f"contract {name} {{\n{state_vars}\n}}",
                            type="state",
                            name=f"{name}_state",
                        )
                    )

            # Extract each function
            for func_match in function_pattern.finditer(contract_code):
                func_start = func_match.start()
                brace_count = 0
                func_end = func_start

                brace_start = contract_code.find("{", func_start)
                for i in range(brace_start, len(contract_code)):
                    if contract_code[i] == "{":
                        brace_count += 1
                    elif contract_code[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            func_end = i + 1
                            break

                func_code = contract_code[func_start:func_end]
                chunks.append(
                    CodeChunk(content=func_code, type="function", name=func_match.group(1))
                )

    # If no contracts found, fall back to token-based
    if not chunks:
        return chunk_by_tokens(code, max_tokens, RAGConfig.chunk_overlap)

    return chunks


def chunk_solidity_code(code: str) -> list[CodeChunk]:
    """Main chunking function."""
    max_tokens = RAGConfig.chunk_size

    # Try regex-based chunking (tree-sitter often not available)
    return chunk_solidity_regex(code, max_tokens)


def prepare_chunks_for_embedding(chunks: list[CodeChunk]) -> list[str]:
    """Combine related chunks if under limit."""
    max_tokens = RAGConfig.chunk_size
    result: list[str] = []
    current_chunk = ""
    current_tokens = 0

    for chunk in chunks:
        chunk_tokens = estimate_tokens(chunk.content)

        if current_tokens + chunk_tokens <= max_tokens:
            current_chunk += ("\n\n" if current_chunk else "") + chunk.content
            current_tokens += chunk_tokens
        else:
            if current_chunk:
                result.append(current_chunk)
            current_chunk = chunk.content
            current_tokens = chunk_tokens

    if current_chunk:
        result.append(current_chunk)

    return result
