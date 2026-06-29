"""
Parser for DeFiHackLabs exploit PoC files.

Extracts metadata and code from Foundry test files.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ParsedExploit:
    """Parsed exploit document."""

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


def parse_exploit_file(file_path: Path) -> ParsedExploit | None:
    """Parse a DeFiHackLabs exploit PoC file."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"  Failed to read {file_path}: {e}")
        return None

    # Extract name from filename (e.g., "Euler_exp.sol" -> "Euler")
    name = file_path.stem.replace("_exp", "").replace("_exploit", "")

    # Extract date from directory structure or comments
    date = extract_date(file_path, content)

    # Extract chain from content
    chain = extract_chain(content)

    # Extract loss amount from comments
    loss_usd = extract_loss(content)

    # Extract attack type from comments or code patterns
    attack_type = extract_attack_type(content)

    # Extract root cause from comments
    root_cause = extract_root_cause(content)

    # Generate summary from comments and code
    summary = extract_summary(content, name)

    # Extract attack flow from test function
    attack_flow = extract_attack_flow(content)

    # Clean PoC code (remove large imports, keep relevant parts)
    poc_code = clean_poc_code(content)

    # Generate unique ID
    doc_id = f"{chain}_{name}_{date}".lower().replace(" ", "_")

    return ParsedExploit(
        id=doc_id,
        name=name,
        date=date,
        chain=chain,
        loss_usd=loss_usd,
        attack_type=attack_type,
        root_cause=root_cause,
        summary=summary,
        attack_flow=attack_flow,
        poc_code=poc_code,
        file_path=str(file_path),
    )


def extract_date(file_path: Path, content: str) -> str:
    """Extract date from file path or content."""
    # Try to extract from directory structure (e.g., "2023-03" or "230301")
    path_str = str(file_path)

    # Match YYYY-MM or YYMMDD patterns
    date_match = re.search(r"(\d{4}-\d{2})", path_str)
    if date_match:
        return date_match.group(1)

    date_match = re.search(r"(\d{6})", path_str)
    if date_match:
        d = date_match.group(1)
        return f"20{d[:2]}-{d[2:4]}"

    # Try to extract from comments
    comment_date = re.search(r"(?:date|Date):\s*(\d{4}[-/]\d{2}[-/]?\d{0,2})", content)
    if comment_date:
        return comment_date.group(1)[:7].replace("/", "-")

    return "unknown"


def extract_chain(content: str) -> str:
    """Extract chain from content."""
    content_lower = content.lower()

    # Check for fork URL patterns
    if "mainnet" in content_lower or "etherscan" in content_lower:
        return "ethereum"
    if "bsc" in content_lower or "bscscan" in content_lower:
        return "bsc"
    if "polygon" in content_lower or "polygonscan" in content_lower:
        return "polygon"
    if "arbitrum" in content_lower or "arbiscan" in content_lower:
        return "arbitrum"
    if "optimism" in content_lower:
        return "optimism"
    if "avalanche" in content_lower or "avax" in content_lower:
        return "avalanche"
    if "fantom" in content_lower or "ftmscan" in content_lower:
        return "fantom"
    if "basescan" in content_lower or ("base" in content_lower and "base_" in content_lower):
        return "base"

    return "ethereum"  # Default


def extract_loss(content: str) -> float | None:
    """Extract loss amount from content."""
    # Match patterns like "~$1.7M" or "$1,700,000" or "1.7 million"
    patterns = [
        r"\$\s*~?\s*([\d,]+\.?\d*)\s*[Mm](?:illion)?",  # $1.7M, $1.7 million
        r"\$\s*~?\s*([\d,]+\.?\d*)\s*[Kk]",  # $170K
        r"\$\s*~?\s*([\d,]+(?:,\d{3})*(?:\.\d+)?)",  # $1,700,000
        r"([\d,]+\.?\d*)\s*(?:USD|USDT|USDC|DAI)",  # 1700000 USDT
        r"lost[:\s]+([\d,]+\.?\d*)\s*(?:USD|ETH|\$)",  # lost: 1700000 USD
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            value_str = match.group(1).replace(",", "")
            try:
                value = float(value_str)
                # Normalize to USD
                if "M" in pattern.lower() or "million" in pattern.lower():
                    value *= 1_000_000
                elif "K" in pattern.lower():
                    value *= 1_000
                return value
            except ValueError:
                continue

    return None


def extract_attack_type(content: str) -> str:
    """Extract attack type from content."""
    content_lower = content.lower()

    attack_types = [
        ("reentrancy", ["reentrancy", "reentrant", "re-entrancy"]),
        ("flash_loan", ["flashloan", "flash loan", "flashbots"]),
        ("price_manipulation", ["price manipulation", "oracle manipulation", "price oracle"]),
        ("access_control", ["access control", "unauthorized", "permission", "onlyowner"]),
        ("integer_overflow", ["overflow", "underflow", "integer"]),
        ("front_running", ["frontrun", "front-run", "sandwich"]),
        ("logic_error", ["logic error", "business logic", "incorrect logic"]),
        ("signature", ["signature", "ecrecover", "replay"]),
        ("delegate_call", ["delegatecall", "delegate call"]),
        ("self_destruct", ["selfdestruct", "self-destruct"]),
    ]

    for attack_type, keywords in attack_types:
        if any(kw in content_lower for kw in keywords):
            return attack_type

    return "unknown"


def extract_root_cause(content: str) -> str:
    """Extract root cause from comments."""
    # Look for root cause comments
    patterns = [
        r"root\s*cause[:\s]*(.*?)(?:\n|$)",
        r"vulnerability[:\s]*(.*?)(?:\n|$)",
        r"issue[:\s]*(.*?)(?:\n|$)",
        r"bug[:\s]*(.*?)(?:\n|$)",
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            cause = match.group(1).strip()
            if len(cause) > 10:
                return cause[:500]

    return ""


def extract_summary(content: str, name: str) -> str:
    """Generate summary from content."""
    # Look for description comments
    desc_patterns = [
        r"/\*\*([\s\S]*?)\*/",  # Multiline comment
        r"//\s*(.+(?:\n//\s*.+)*)",  # Single line comments
    ]

    for pattern in desc_patterns:
        match = re.search(pattern, content)
        if match:
            desc = match.group(1)
            # Clean up
            desc = re.sub(r"[/*]", "", desc)
            desc = re.sub(r"\s+", " ", desc).strip()
            if len(desc) > 50:
                return desc[:1000]

    return f"Exploit PoC for {name} vulnerability"


def extract_attack_flow(content: str) -> str:
    """Extract attack flow from test function."""
    # Find testExploit or similar function
    func_patterns = [
        r"function\s+test\w*\(\)[^{]*\{([\s\S]*?)\n\s*\}",
        r"function\s+exploit\w*\(\)[^{]*\{([\s\S]*?)\n\s*\}",
    ]

    for pattern in func_patterns:
        match = re.search(pattern, content)
        if match:
            body = match.group(1)
            # Extract key steps (lines with function calls)
            steps = []
            for line in body.split("\n"):
                line = line.strip()
                if line and not line.startswith("//") and "(" in line:
                    steps.append(line)

            if steps:
                return "\n".join(steps[:20])

    return ""


def clean_poc_code(content: str) -> str:
    """Clean PoC code for storage."""
    # Remove large import blocks
    content = re.sub(r'import\s+"[^"]+";?\s*\n?', "", content)
    content = re.sub(r"import\s+\{[^}]+\}\s+from\s+[^;]+;?\s*\n?", "", content)

    # Remove forge-std boilerplate
    content = re.sub(r"// SPDX-License-Identifier:[^\n]+\n?", "", content)
    content = re.sub(r"pragma solidity[^;]+;\s*\n?", "", content)

    # Truncate if too long
    if len(content) > 10000:
        content = content[:10000] + "\n// ... truncated ..."

    return content.strip()


def parse_defihacklabs_directory(
    base_path: Path, limit: int | None = None
) -> list[ParsedExploit]:
    """Parse all exploit files in DeFiHackLabs directory."""
    exploits: list[ParsedExploit] = []

    # Find all .sol files in src directory
    sol_files = list(base_path.glob("src/**/*.sol"))

    # Filter to likely exploit files
    exploit_files = [
        f
        for f in sol_files
        if "_exp" in f.name.lower()
        or "exploit" in f.name.lower()
        or "test" in f.name.lower()
    ]

    print(f"Found {len(exploit_files)} potential exploit files")

    for i, file_path in enumerate(exploit_files):
        if limit and i >= limit:
            break

        exploit = parse_exploit_file(file_path)
        if exploit:
            exploits.append(exploit)
            if (i + 1) % 50 == 0:
                print(f"  Parsed {i + 1}/{len(exploit_files)} files")

    print(f"Successfully parsed {len(exploits)} exploits")
    return exploits


def to_document_dict(exploit: ParsedExploit) -> dict[str, Any]:
    """Convert ParsedExploit to dictionary for insertion."""
    return {
        "id": exploit.id,
        "name": exploit.name,
        "date": exploit.date,
        "chain": exploit.chain,
        "loss_usd": exploit.loss_usd,
        "attack_type": exploit.attack_type,
        "root_cause": exploit.root_cause,
        "summary": exploit.summary,
        "attack_flow": exploit.attack_flow,
        "poc_code": exploit.poc_code,
        "file_path": exploit.file_path,
    }
