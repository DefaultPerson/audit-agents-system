"""
CLI interface for audit-agents.
Built with Typer and Rich.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit, urlunsplit

import typer
from rich.console import Console
from rich.table import Table

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import UTC

from src.config import CHAINS, AuditConfig, get_audit_dir
from src.db import get_db
from src.logger import setup_logger
from src.models import Chain, ContractStatus

app = typer.Typer(
    name="audit",
    no_args_is_help=True,
)
console = Console()


def _mask_rpc_url(rpc_url: str) -> str:
    """Mask userinfo/query credentials before printing RPC URLs."""
    try:
        parsed = urlsplit(rpc_url)
    except ValueError:
        return "<invalid-url>"
    netloc = parsed.netloc
    if "@" in netloc:
        host = netloc.rsplit("@", 1)[1]
        netloc = f"<redacted>@{host}"
    query = "<redacted>" if parsed.query else ""
    masked = urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))
    return masked[:50] + "..." if len(masked) > 50 else masked


@app.callback()
def main_callback(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Verbose output (INFO level)")
    ] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Debug output (DEBUG level)")] = False,
):
    """Autonomous smart contract security audit system."""
    level = "DEBUG" if debug else ("INFO" if verbose else "WARNING")
    setup_logger(level=level)


# ============================================
# Database Commands
# ============================================

db_app = typer.Typer(help="Database operations")
app.add_typer(db_app, name="db")


@db_app.command("init")
def db_init():
    """Initialize the database."""
    with get_db():
        console.print(f"[green]Database initialized at {AuditConfig.db_path}[/green]")


@db_app.command("stats")
def db_stats(json_output: Annotated[bool, typer.Option("--json", "-j")] = False):
    """Show database statistics."""
    with get_db() as db:
        stats = db.get_stats()

        if json_output:
            console.print_json(stats.model_dump_json(by_alias=True))
            return

        table = Table(title="Database Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Contracts", str(stats.total))
        table.add_row("Total Value (USD)", f"${stats.total_value_usd:,.2f}")

        for status, count in stats.by_status.items():
            table.add_row(f"Status: {status}", str(count))

        for chain, count in stats.by_chain.items():
            table.add_row(f"Chain: {chain.upper()}", str(count))

        console.print(table)


@db_app.command("list")
def db_list(
    status: Annotated[str, typer.Argument(help="Contract status")] = "new",
    limit: Annotated[int, typer.Option("--limit", "-n")] = 10,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """List contracts by status."""
    try:
        contract_status = ContractStatus(status)
    except ValueError:
        console.print(f"[red]Invalid status: {status}[/red]")
        console.print(f"Valid statuses: {', '.join(s.value for s in ContractStatus)}")
        raise typer.Exit(1) from None

    with get_db() as db:
        contracts = db.get_contracts_by_status(contract_status, limit)

        if json_output:
            data = [c.model_dump(by_alias=True, mode="json") for c in contracts]
            console.print_json(json.dumps(data))
            return

        if not contracts:
            console.print(f"[yellow]No contracts with status '{status}'[/yellow]")
            return

        table = Table(title=f"Contracts ({status})")
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Chain", style="blue")
        table.add_column("Balance USD", style="green", justify="right")
        table.add_column("Age (days)", justify="right")
        table.add_column("Proxy", justify="center")

        for c in contracts:
            table.add_row(
                c.address[:10] + "..." + c.address[-6:],
                c.chain.value.upper(),
                f"${c.balance_usd:,.0f}",
                str(c.age),
                "Yes" if c.is_proxy else "No",
            )

        console.print(table)


# ============================================
# Queue Commands
# ============================================

queue_app = typer.Typer(help="Queue operations")
app.add_typer(queue_app, name="queue")


@queue_app.command("stats")
def queue_stats(json_output: Annotated[bool, typer.Option("--json", "-j")] = False):
    """Show queue statistics."""
    with get_db() as db:
        stats = db.get_queue_stats()

        if json_output:
            console.print_json(stats.model_dump_json(by_alias=True))
            return

        table = Table(title="Queue Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total", str(stats.total))
        table.add_row("Pending", str(stats.pending))
        table.add_row("Processing", str(stats.processing))
        table.add_row("Done", str(stats.done))
        table.add_row("Failed", str(stats.failed))
        table.add_row("Success Rate", f"{stats.success_rate}%")
        table.add_row("Total Value (USD)", f"${stats.total_value:,.2f}")

        for chain, count in stats.by_chain.items():
            table.add_row(f"Chain: {chain}", str(count))

        console.print(table)


@queue_app.command("list")
def queue_list(
    limit: Annotated[int, typer.Option("--limit", "-n")] = 20,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """List queue items."""
    with get_db() as db:
        items = db.get_queue(limit)

        if json_output:
            data = [item.model_dump(mode="json") for item in items]
            console.print_json(json.dumps(data))
            return

        if not items:
            console.print("[yellow]Queue is empty[/yellow]")
            return

        table = Table(title="Audit Queue")
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Chain", style="blue")
        table.add_column("Status", style="magenta")
        table.add_column("Priority", justify="right")
        table.add_column("Balance USD", style="green", justify="right")

        for item in items:
            status_color = {
                "pending": "yellow",
                "processing": "blue",
                "done": "green",
                "failed": "red",
            }.get(item.status.value, "white")

            table.add_row(
                item.address[:10] + "..." + item.address[-6:],
                item.chain.upper(),
                f"[{status_color}]{item.status.value}[/{status_color}]",
                str(item.priority),
                f"${item.balance_usd:,.0f}" if item.balance_usd else "-",
            )

        console.print(table)


@queue_app.command("add")
def queue_add(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    priority: Annotated[int, typer.Option("--priority", "-p")] = 0,
    balance: Annotated[float, typer.Option("--balance", "-b")] = 0,
):
    """Add contract to queue."""
    try:
        chain_enum = Chain(chain.lower())
    except ValueError:
        console.print(f"[red]Invalid chain: {chain}[/red]")
        console.print(f"Valid chains: {', '.join(c.value for c in Chain)}")
        raise typer.Exit(1) from None

    with get_db() as db:
        db.add_to_queue(address, chain_enum, balance, priority)
        console.print(f"[green]Added {address} to queue[/green]")


@queue_app.command("clear")
def queue_clear(
    force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")] = False,
):
    """Clear the queue."""
    if not force:
        confirm = typer.confirm("Are you sure you want to clear the queue?")
        if not confirm:
            raise typer.Abort()

    with get_db() as db:
        db.clear_queue()
        console.print("[green]Queue cleared[/green]")


# ============================================
# Config Commands
# ============================================

config_app = typer.Typer(help="Configuration")
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show():
    """Show current configuration."""
    table = Table(title="Chain Configuration")
    table.add_column("Chain", style="cyan")
    table.add_column("Chain ID", justify="right")
    table.add_column("RPC URL", style="blue", no_wrap=True)
    table.add_column("API Key", justify="center")

    for chain_id, config in CHAINS.items():
        has_key = "Yes" if config.explorer_api_key else "No"
        rpc_display = _mask_rpc_url(config.rpc_url)
        table.add_row(
            chain_id.upper(),
            str(config.chain_id),
            rpc_display,
            has_key,
        )

    console.print(table)

    # Audit config
    table2 = Table(title="Audit Configuration")
    table2.add_column("Setting", style="cyan")
    table2.add_column("Value", style="green")

    table2.add_row("Min Balance (USD)", f"${AuditConfig.min_balance_usd:,}")
    table2.add_row("Min Age (days)", str(AuditConfig.min_age_days))
    table2.add_row("Database Path", str(AuditConfig.db_path))
    table2.add_row("Audits Dir", str(AuditConfig.audits_dir))

    console.print(table2)


@config_app.command("set-dedaub-cookies")
def config_set_dedaub_cookies(
    from_file: Annotated[Path | None, typer.Option("--from-file")] = None,
    env_file: Annotated[Path, typer.Option("--env-file")] = Path(".env"),
):
    """Update DEDAUB_COOKIES in a local dotenv file from stdin or a file."""
    from src.local_env import set_env_value

    if from_file:
        cookies = from_file.read_text(encoding="utf-8").strip()
    else:
        if sys.stdin.isatty():
            console.print("[red]Pass cookies through stdin or --from-file.[/red]")
            raise typer.Exit(1)
        cookies = sys.stdin.read().strip()

    if not cookies:
        console.print("[red]No cookie value provided.[/red]")
        raise typer.Exit(1)

    set_env_value(env_file, "DEDAUB_COOKIES", cookies)
    console.print(f"[green]Updated DEDAUB_COOKIES in {env_file}[/green]")
    console.print("[yellow]Cookie value was not printed. Keep this file out of git.[/yellow]")


# ============================================
# Benchmark Commands
# ============================================

benchmark_app = typer.Typer(help="Benchmark corpus scoring")
app.add_typer(benchmark_app, name="benchmark")


@benchmark_app.command("score")
def benchmark_score(
    corpus_path: Annotated[Path, typer.Argument(help="Benchmark corpus JSON")],
    report_paths: Annotated[list[Path], typer.Argument(help="Internal report JSON files")],
    output_path: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Score internal autoresearch reports against a benchmark corpus."""
    from src.benchmark import load_corpus, score_internal_reports, write_benchmark_summary

    corpus = load_corpus(corpus_path)
    summary = score_internal_reports(corpus, report_paths)

    if output_path:
        write_benchmark_summary(summary, output_path)

    if json_output:
        console.print_json(summary.model_dump_json(by_alias=True))
        return

    table = Table(title=f"Benchmark: {summary.corpus_name}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Total Cases", str(summary.total_cases))
    table.add_row("Scored Cases", str(summary.scored_cases))
    table.add_row("Known Exploit Recall", f"{summary.known_exploit_recall:.2%}")
    table.add_row("Benign False Positive Rate", f"{summary.benign_false_positive_rate:.2%}")
    table.add_row("Edge Cases Attempted", str(summary.edge_case_validated))
    table.add_row("Missing Cases", str(len(summary.missing_case_ids)))
    console.print(table)

    if summary.missing_case_ids:
        console.print("\n[yellow]Missing case ids:[/yellow]")
        for case_id in summary.missing_case_ids[:20]:
            console.print(f"  - {case_id}")
        if len(summary.missing_case_ids) > 20:
            console.print(f"  ... and {len(summary.missing_case_ids) - 20} more")

    if output_path:
        console.print(f"\n[cyan]Summary saved: {output_path}[/cyan]")


@benchmark_app.command("plan")
def benchmark_plan(
    corpus_path: Annotated[Path, typer.Argument(help="Benchmark corpus JSON")],
    output_path: Annotated[Path, typer.Option("--output", "-o")],
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("benchmark-runs"),
    model_pair_specs: Annotated[
        list[str] | None,
        typer.Option(
            "--model-pair",
            help="MODEL or ID=RESEARCHER:SKEPTIC. Repeat for multiple pairs.",
        ),
    ] = None,
    iterations: Annotated[int, typer.Option("--iterations", "-n", min=1)] = 3,
    skip_dedaub: Annotated[bool, typer.Option("--skip-dedaub/--use-dedaub")] = True,
    run_validators: Annotated[bool, typer.Option("--validate/--no-validate")] = False,
    materialize_tools: Annotated[
        bool, typer.Option("--materialize-tools/--no-materialize-tools")
    ] = False,
    cost_budget_usd: Annotated[float | None, typer.Option("--cost-budget-usd")] = None,
    time_budget_seconds: Annotated[int | None, typer.Option("--time-budget-seconds")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Create a corpus x model-pair benchmark run plan."""
    from src.benchmark import (
        build_benchmark_run_plan,
        load_corpus,
        parse_model_pairs,
        write_benchmark_run_plan,
    )

    pairs = parse_model_pairs(model_pair_specs or ["offline-deterministic:offline-consensus-gate"])
    plan = build_benchmark_run_plan(
        load_corpus(corpus_path),
        output_dir=output_dir,
        model_pairs=pairs,
        iterations=iterations,
        skip_dedaub=skip_dedaub,
        validate=run_validators,
        materialize_tools=materialize_tools,
        cost_budget_usd=cost_budget_usd,
        time_budget_seconds=time_budget_seconds,
    )
    write_benchmark_run_plan(plan, output_path)

    if json_output:
        console.print_json(plan.model_dump_json(by_alias=True))
        return

    console.print("[green]Benchmark run plan created[/green]")
    console.print(f"  Plan: {output_path}")
    console.print(f"  Items: {len(plan.items)}")
    console.print(f"  Model pairs: {len(plan.model_pairs)}")


@benchmark_app.command("run")
def benchmark_run(
    plan_path: Annotated[Path, typer.Argument(help="Benchmark run plan JSON")],
    output_path: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    receipts_dir: Annotated[Path | None, typer.Option("--receipts-dir")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Execute a benchmark run plan and write receipts."""
    from src.benchmark import (
        execute_benchmark_run_plan,
        load_benchmark_run_plan,
        write_benchmark_run_execution,
    )

    plan = load_benchmark_run_plan(plan_path)
    execution = execute_benchmark_run_plan(plan, receipts_dir=receipts_dir)
    execution.plan_path = str(plan_path)
    target_output_path = output_path or Path(plan.output_dir) / "execution.json"
    write_benchmark_run_execution(execution, target_output_path)

    if json_output:
        console.print_json(execution.model_dump_json(by_alias=True))
        return

    failed = sum(1 for receipt in execution.receipts if receipt.return_code != 0)
    console.print("[green]Benchmark run complete[/green]")
    console.print(f"  Execution: {target_output_path}")
    console.print(f"  Receipts: {len(execution.receipts)}")
    console.print(f"  Reports: {len(execution.report_paths)}")
    if failed:
        console.print(f"[yellow]  Failed items: {failed}[/yellow]")


# ============================================
# Disclosure Commands
# ============================================

disclosure_app = typer.Typer(help="Manual disclosure draft generation")
app.add_typer(disclosure_app, name="disclosure")


@disclosure_app.command("draft")
def disclosure_draft(
    report_path: Annotated[Path, typer.Argument(help="Internal report JSON")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir", "-o")] = None,
):
    """Create a local disclosure draft from validated evidence. Never sends it."""
    from src.disclosure import write_disclosure_draft

    target_output_dir = output_dir or report_path.parent.parent / "disclosure"
    try:
        draft_path = write_disclosure_draft(report_path, target_output_dir)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None

    console.print("[green]Disclosure draft created[/green]")
    console.print(f"  Draft: {draft_path}")
    console.print("[yellow]Manual approval is still required before contact.[/yellow]")


@disclosure_app.command("package")
def disclosure_package(
    report_path: Annotated[Path, typer.Argument(help="Internal report JSON")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir", "-o")] = None,
    owner_contact: Annotated[str | None, typer.Option("--owner-contact")] = None,
    owner_lookup_notes: Annotated[str | None, typer.Option("--owner-lookup-notes")] = None,
    owner_lookup_path: Annotated[Path | None, typer.Option("--owner-lookup-path")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Create a local reproduction package. Never sends it."""
    from src.disclosure import write_reproduction_package

    target_output_dir = output_dir or report_path.parent.parent / "disclosure"
    try:
        package_dir, manifest, _state = write_reproduction_package(
            report_path,
            target_output_dir,
            owner_contact=owner_contact,
            owner_lookup_notes=owner_lookup_notes,
            owner_lookup_path=str(owner_lookup_path) if owner_lookup_path else None,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None

    if json_output:
        console.print_json(manifest.model_dump_json(by_alias=True))
        return

    console.print("[green]Disclosure reproduction package created[/green]")
    console.print(f"  Package: {package_dir}")
    console.print(f"  Manifest: {package_dir / 'manifest.json'}")
    console.print(f"  Contact state: {package_dir / 'contact_state.json'}")
    console.print("[yellow]Manual approval is still required before contact.[/yellow]")


@disclosure_app.command("approve")
def disclosure_approve(
    state_path: Annotated[Path, typer.Argument(help="contact_state.json path")],
    approved_by: Annotated[str, typer.Option("--approved-by")],
    finding_severity: Annotated[str | None, typer.Option("--severity")] = None,
    owner_contact: Annotated[str | None, typer.Option("--owner-contact")] = None,
    owner_lookup_notes: Annotated[str | None, typer.Option("--owner-lookup-notes")] = None,
    owner_lookup_path: Annotated[Path | None, typer.Option("--owner-lookup-path")] = None,
    notes: Annotated[str | None, typer.Option("--notes")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Record manual disclosure approval. Never sends it."""
    from src.disclosure import approve_contact_state

    try:
        state = approve_contact_state(
            state_path,
            approved_by=approved_by,
            finding_severity=finding_severity,
            owner_contact=owner_contact,
            owner_lookup_notes=owner_lookup_notes,
            owner_lookup_path=str(owner_lookup_path) if owner_lookup_path else None,
            notes=notes,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None
    if json_output:
        console.print_json(state.model_dump_json(by_alias=True))
        return

    console.print("[green]Disclosure state approved locally[/green]")
    console.print(f"  Status: {state.status.value}")
    console.print(f"  Severity: {state.finding_severity.value if state.finding_severity else 'unset'}")
    console.print(f"  Contact state: {state_path}")
    console.print("[yellow]No message was sent.[/yellow]")


@disclosure_app.command("owner-lookup")
def disclosure_owner_lookup(
    report_path: Annotated[Path, typer.Argument(help="Internal report JSON")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir", "-o")] = None,
    state_path: Annotated[Path | None, typer.Option("--state-path")] = None,
    rpc_url: Annotated[str | None, typer.Option("--rpc-url")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Read owner/admin candidates into a local artifact. Never sends it."""
    from src.disclosure import write_owner_lookup

    target_output_dir = output_dir or report_path.parent.parent / "disclosure"
    path, result = asyncio.run(
        write_owner_lookup(
            report_path,
            target_output_dir,
            rpc_url=rpc_url,
            state_path=state_path,
        )
    )

    if json_output:
        console.print_json(result.model_dump_json(by_alias=True))
        return

    console.print("[green]Owner lookup artifact created[/green]")
    console.print(f"  Owner lookup: {path}")
    console.print(f"  Candidates: {len(result.candidates)}")
    console.print(f"  Errors: {len(result.errors)}")
    console.print("[yellow]Manual verification is required before contact.[/yellow]")


# ============================================
# Triage Command
# ============================================


@app.command("triage")
def triage(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Triage a contract to determine if it should be audited."""
    from src.stages.triage import triage_contract

    try:
        chain_enum = Chain(chain.lower())
    except ValueError:
        console.print(f"[red]Invalid chain: {chain}[/red]")
        raise typer.Exit(1) from None

    console.print(f"[cyan]Triaging {address} on {chain.upper()}...[/cyan]")

    result = asyncio.run(triage_contract(address, chain_enum))

    if json_output:
        console.print_json(result.model_dump_json(by_alias=True))
        return

    table = Table(title="Triage Result")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Address", result.address)
    table.add_row("Chain", result.chain.value.upper())
    table.add_row("Passed", "[green]Yes[/green]" if result.passed else "[red]No[/red]")
    table.add_row("Skip Reason", result.skip_reason.value if result.skip_reason else "-")
    table.add_row("Is Proxy", "Yes" if result.is_proxy else "No")
    table.add_row("Code Hash", result.code_hash[:16] + "..." if result.code_hash else "-")
    table.add_row("Code Size", f"{result.code_size} bytes")
    table.add_row("Confidence", f"{result.confidence * 100:.0f}%")

    console.print(table)


# ============================================
# Resolve Command
# ============================================


@app.command("resolve")
def resolve(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Resolve a contract (detect proxy, extract selectors)."""
    from src.stages.resolve import resolve_contract

    try:
        chain_enum = Chain(chain.lower())
    except ValueError:
        console.print(f"[red]Invalid chain: {chain}[/red]")
        raise typer.Exit(1) from None

    console.print(f"[cyan]Resolving {address} on {chain.upper()}...[/cyan]")

    result = asyncio.run(resolve_contract(address, chain_enum))

    if json_output:
        console.print_json(result.model_dump_json(by_alias=True))
        return

    table = Table(title="Resolve Result")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Original Address", result.original_address)
    table.add_row("Resolved Address", result.resolved_address)
    table.add_row("Chain", result.chain.value.upper())
    table.add_row("Is Proxy", "[yellow]Yes[/yellow]" if result.is_proxy else "No")
    table.add_row("Proxy Type", result.proxy_type.value if result.proxy_type else "-")
    table.add_row("Selectors", str(len(result.selectors or [])))

    console.print(table)

    if result.selectors:
        console.print("\n[cyan]Function Selectors:[/cyan]")
        for sel in result.selectors[:20]:
            console.print(f"  {sel}")
        if len(result.selectors or []) > 20:
            console.print(f"  ... and {len(result.selectors) - 20} more")


# ============================================
# Decompile Command
# ============================================


@app.command("decompile")
def decompile(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    skip_dedaub: Annotated[bool, typer.Option("--skip-dedaub")] = False,
):
    """Decompile a contract using Dedaub API."""
    from src.stages.decompile import decompile_contract
    from src.stages.resolve import get_bytecode

    try:
        chain_enum = Chain(chain.lower())
    except ValueError:
        console.print(f"[red]Invalid chain: {chain}[/red]")
        raise typer.Exit(1) from None

    console.print(f"[cyan]Decompiling {address} on {chain.upper()}...[/cyan]")

    # Get bytecode first
    bytecode = asyncio.run(get_bytecode(address, chain_enum))
    if not bytecode:
        console.print("[red]No bytecode found[/red]")
        raise typer.Exit(1)

    success, output_dir, sol_file = asyncio.run(
        decompile_contract(
            address,
            chain_enum,
            bytecode.hex(),
            skip_dedaub=skip_dedaub,
        )
    )

    if success:
        console.print("[green]Decompilation successful![/green]")
        console.print(f"  Output directory: {output_dir}")
        if sol_file:
            console.print(f"  Solidity file: {sol_file}")
    else:
        console.print("[red]Decompilation failed[/red]")
        raise typer.Exit(1)


# ============================================
# Full Audit Command
# ============================================


@app.command("audit")
def audit(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    balance: Annotated[float, typer.Option("--balance", "-b")] = 0,
    with_rag: Annotated[bool, typer.Option("--with-rag")] = True,
    skip_dedaub: Annotated[bool, typer.Option("--skip-dedaub")] = False,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Run full audit on a contract."""
    from src.daemon import run_single_audit

    try:
        Chain(chain.lower())
    except ValueError:
        console.print(f"[red]Invalid chain: {chain}[/red]")
        raise typer.Exit(1) from None

    console.print(f"[cyan]Running full audit on {address} ({chain.upper()})...[/cyan]")
    console.print(f"  RAG: {'Yes' if with_rag else 'No'}")
    console.print()

    result, findings, report_path = asyncio.run(
        run_single_audit(
            address=address,
            chain=chain.lower(),
            balance_usd=balance,
            use_rag=with_rag,
            skip_dedaub=skip_dedaub,
            verbose=not json_output,
        )
    )

    if json_output:
        data = {
            "status": result.value,
            "findings_count": len(findings),
            "findings": [f.model_dump(by_alias=True, mode="json") for f in findings],
            "report_path": report_path,
        }
        console.print_json(json.dumps(data))
        return

    console.print()
    if result.value == "vulnerable":
        console.print(f"[red]VULNERABLE - {len(findings)} findings[/red]")
    elif result.value == "clean":
        console.print("[green]CLEAN - No vulnerabilities found[/green]")
    else:
        console.print(f"[yellow]ERROR - {result.value}[/yellow]")

    if report_path:
        console.print(f"\n[cyan]Report saved: {report_path}[/cyan]")


# ============================================
# Evidence-Gated Autoresearch Command
# ============================================


@app.command("propose-hypotheses")
def propose_hypotheses(
    artifact_bundle: Annotated[Path, typer.Argument(help="Path to artifact_bundle.json")],
    cheap_facts: Annotated[Path | None, typer.Option("--cheap-facts")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    researcher_model: Annotated[
        str, typer.Option("--researcher-model", envvar="AUTORESEARCH_RESEARCHER_MODEL")
    ] = "gpt-5.2",
    skeptic_model: Annotated[
        str, typer.Option("--skeptic-model", envvar="AUTORESEARCH_SKEPTIC_MODEL")
    ] = "gpt-5.2",
    base_url: Annotated[
        str, typer.Option("--base-url", envvar="AUTORESEARCH_OPENAI_BASE_URL")
    ] = "https://api.openai.com/v1",
    api_key: Annotated[str | None, typer.Option("--api-key", envvar="AUTORESEARCH_API_KEY")] = None,
    temperature: Annotated[float, typer.Option("--temperature", min=0.0, max=2.0)] = 0.1,
    max_tokens: Annotated[int, typer.Option("--max-tokens", min=256)] = 4096,
    timeout_seconds: Annotated[float, typer.Option("--timeout-seconds", min=1.0)] = 120.0,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Generate external hypotheses with Researcher/Skeptic models."""
    from src.autoresearch import (
        OpenAICompatibleConfig,
        generate_model_hypotheses,
        load_artifact_bundle,
    )

    if api_key is None:
        console.print("[red]Missing API key. Set AUTORESEARCH_API_KEY or pass --api-key.[/red]")
        raise typer.Exit(1)

    bundle = load_artifact_bundle(artifact_bundle)
    facts_path = cheap_facts or artifact_bundle.parent / "cheap_facts.json"
    if not facts_path.exists():
        console.print(f"[red]Cheap facts file not found: {facts_path}[/red]")
        raise typer.Exit(1)
    facts_data = json.loads(facts_path.read_text(encoding="utf-8"))
    if not isinstance(facts_data, list) or not all(isinstance(item, str) for item in facts_data):
        console.print("[red]Cheap facts file must be a JSON array of strings.[/red]")
        raise typer.Exit(1)

    handoff_dir = output_dir or artifact_bundle.parent.parent / "autoresearch" / "model_handoff"
    result = asyncio.run(
        generate_model_hypotheses(
            bundle=bundle,
            cheap_facts=facts_data,
            output_dir=handoff_dir,
            config=OpenAICompatibleConfig(
                base_url=base_url,
                api_key=api_key,
                researcher_model=researcher_model,
                skeptic_model=skeptic_model,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
            ),
        )
    )

    if json_output:
        console.print_json(
            json.dumps(
                {
                    "hypothesesPath": str(result.hypotheses_path),
                    "transcriptPath": str(result.transcript_path),
                    "hypothesisCount": len(result.hypotheses),
                    "researcherModel": result.researcher_model,
                    "skepticModel": result.skeptic_model,
                }
            )
        )
        return

    console.print("[green]Model hypotheses generated[/green]")
    console.print(f"  Hypotheses file: {result.hypotheses_path}")
    console.print(f"  Transcript: {result.transcript_path}")
    console.print(f"  Hypotheses: {len(result.hypotheses)}")
    console.print(
        "  Next: audit autoresearch <address> --chain <chain> "
        f"--hypotheses-file {result.hypotheses_path}"
    )


@app.command("autoresearch")
def autoresearch(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    iterations: Annotated[int, typer.Option("--iterations", "-n", min=1)] = 6,
    snapshot_block: Annotated[int | None, typer.Option("--block")] = None,
    bytecode_file: Annotated[Path | None, typer.Option("--bytecode-file")] = None,
    decompile_dir_override: Annotated[Path | None, typer.Option("--decompile-dir")] = None,
    dedaub_file_override: Annotated[Path | None, typer.Option("--dedaub-file")] = None,
    resolved_address: Annotated[str | None, typer.Option("--resolved-address")] = None,
    selectors: Annotated[str | None, typer.Option("--selectors")] = None,
    is_proxy: Annotated[bool, typer.Option("--is-proxy")] = False,
    proxy_type: Annotated[str | None, typer.Option("--proxy-type")] = None,
    hypotheses_file: Annotated[Path | None, typer.Option("--hypotheses-file")] = None,
    generate_hypotheses: Annotated[
        bool,
        typer.Option("--generate-hypotheses/--offline-hypotheses"),
    ] = False,
    researcher_model: Annotated[
        str, typer.Option("--researcher-model", envvar="AUTORESEARCH_RESEARCHER_MODEL")
    ] = "offline-deterministic",
    skeptic_model: Annotated[
        str, typer.Option("--skeptic-model", envvar="AUTORESEARCH_SKEPTIC_MODEL")
    ] = "offline-consensus-gate",
    base_url: Annotated[
        str, typer.Option("--base-url", envvar="AUTORESEARCH_OPENAI_BASE_URL")
    ] = "https://api.openai.com/v1",
    api_key: Annotated[str | None, typer.Option("--api-key", envvar="AUTORESEARCH_API_KEY")] = None,
    temperature: Annotated[float, typer.Option("--temperature", min=0.0, max=2.0)] = 0.1,
    max_tokens: Annotated[int, typer.Option("--max-tokens", min=256)] = 4096,
    timeout_seconds: Annotated[float, typer.Option("--timeout-seconds", min=1.0)] = 120.0,
    skip_dedaub: Annotated[bool, typer.Option("--skip-dedaub")] = False,
    run_validators: Annotated[bool, typer.Option("--validate/--no-validate")] = True,
    materialize_tools: Annotated[
        bool, typer.Option("--materialize-tools/--no-materialize-tools")
    ] = True,
    output_dir: Annotated[Path | None, typer.Option("--output-dir", "-o")] = None,
    cost_budget_usd: Annotated[float | None, typer.Option("--cost-budget-usd")] = None,
    time_budget_seconds: Annotated[int | None, typer.Option("--time-budget-seconds")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Run evidence-gated autoresearch prep for one closed-source EVM target."""
    from src.autoresearch import OpenAICompatibleConfig, load_hypotheses_file
    from src.models import ProxyType, ResolvedContract
    from src.stages.autoresearch import run_autoresearch_stage
    from src.stages.decompile import decompile_contract
    from src.stages.resolve import get_bytecode, resolve_contract

    try:
        chain_enum = Chain(chain.lower())
    except ValueError:
        console.print(f"[red]Invalid chain: {chain}[/red]")
        raise typer.Exit(1) from None

    console.print(
        f"[cyan]Running evidence-gated autoresearch prep on {address} ({chain.upper()})...[/cyan]"
    )
    console.print("[yellow]No owner notification will be sent.[/yellow]")
    if generate_hypotheses and hypotheses_file is not None:
        console.print("[red]Use either --generate-hypotheses or --hypotheses-file, not both.[/red]")
        raise typer.Exit(1)
    if generate_hypotheses and api_key is None and "api.openai.com" in base_url:
        console.print("[red]Missing API key. Set AUTORESEARCH_API_KEY or pass --api-key.[/red]")
        raise typer.Exit(1)

    parsed_proxy_type = ProxyType.NONE
    if proxy_type is not None:
        try:
            parsed_proxy_type = ProxyType(proxy_type.lower())
        except ValueError:
            console.print(f"[red]Invalid proxy type: {proxy_type}[/red]")
            raise typer.Exit(1) from None

    if bytecode_file is not None:
        raw_bytecode = bytecode_file.read_text(encoding="utf-8").strip()
        if not raw_bytecode:
            console.print(f"[red]Bytecode file is empty: {bytecode_file}[/red]")
            raise typer.Exit(1)
        bytecode_hex = raw_bytecode.lower().removeprefix("0x")
        try:
            bytes.fromhex(bytecode_hex)
        except ValueError:
            console.print(f"[red]Bytecode file is not valid hex: {bytecode_file}[/red]")
            raise typer.Exit(1) from None
        resolved = ResolvedContract(
            originalAddress=address,
            resolvedAddress=resolved_address or address,
            chain=chain_enum,
            isProxy=is_proxy,
            proxyType=parsed_proxy_type if is_proxy else ProxyType.NONE,
            selectors=[
                selector.strip().lower()
                for selector in (selectors or "").split(",")
                if selector.strip()
            ],
        )
        bytecode_for_decompile = bytecode_hex
    else:
        resolved = asyncio.run(resolve_contract(address, chain_enum, snapshot_block=snapshot_block))
        bytecode = asyncio.run(
            get_bytecode(resolved.resolved_address, chain_enum, snapshot_block=snapshot_block)
        )
        if not bytecode:
            console.print("[red]No bytecode found[/red]")
            raise typer.Exit(1)
        bytecode_for_decompile = bytecode.hex()

    if decompile_dir_override is not None or dedaub_file_override is not None:
        decompile_dir = decompile_dir_override or (
            dedaub_file_override.parent if dedaub_file_override is not None else None
        )
        sol_file = str(dedaub_file_override) if dedaub_file_override is not None else None
        success = sol_file is not None
    else:
        success, decompile_dir, sol_file = asyncio.run(
            decompile_contract(
                resolved.resolved_address,
                chain_enum,
                bytecode_for_decompile,
                skip_dedaub=skip_dedaub,
            )
        )
    if not success:
        console.print("[yellow]Decompilation failed; continuing with bytecode artifacts.[/yellow]")

    proposed_hypotheses = load_hypotheses_file(hypotheses_file) if hypotheses_file else None
    model_handoff_config = (
        OpenAICompatibleConfig(
            base_url=base_url,
            api_key=api_key,
            researcher_model=researcher_model,
            skeptic_model=skeptic_model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
        )
        if generate_hypotheses
        else None
    )

    result = asyncio.run(
        run_autoresearch_stage(
            address=address,
            chain=chain_enum,
            resolved=resolved,
            bytecode_hex=bytecode_for_decompile,
            decompile_dir=decompile_dir,
            dedaub_file=sol_file,
            iteration_budget=iterations,
            snapshot_block=snapshot_block,
            run_validators=run_validators,
            proposed_hypotheses=proposed_hypotheses,
            researcher_model=researcher_model,
            skeptic_model=skeptic_model,
            materialize_tools=materialize_tools,
            audit_dir=output_dir,
            cost_budget_usd=cost_budget_usd,
            time_budget_seconds=time_budget_seconds,
            model_handoff_config=model_handoff_config,
        )
    )

    if json_output:
        console.print_json(
            json.dumps(
                {
                    "artifactPath": str(result.artifact_path),
                    "toolManifestPath": str(result.tool_manifest_path),
                    "statePath": str(result.state_path),
                    "rejectedMemoryPath": str(result.rejected_memory_path),
                    "verificationPackagePaths": [
                        str(path) for path in result.verification_package_paths
                    ],
                    "validationResultPaths": [str(path) for path in result.validation_result_paths],
                    "internalReportPath": str(result.internal_report_path),
                    "internalReportMarkdownPath": str(result.internal_report_md_path),
                    "modelHypothesesPath": (
                        str(result.model_hypotheses_path) if result.model_hypotheses_path else None
                    ),
                    "modelTranscriptPath": (
                        str(result.model_transcript_path) if result.model_transcript_path else None
                    ),
                    "researcherModel": researcher_model,
                    "skepticModel": skeptic_model,
                    "materializedTools": materialize_tools,
                    "consensusCount": result.consensus_count,
                    "rejectedCount": result.rejected_count,
                    "validatedCount": result.validated_count,
                }
            )
        )
        return

    console.print("[green]Autoresearch prep complete[/green]")
    console.print(f"  Artifact bundle: {result.artifact_path}")
    console.print(f"  Tool manifest: {result.tool_manifest_path}")
    console.print(f"  Loop state: {result.state_path}")
    console.print(f"  Rejected memory: {result.rejected_memory_path}")
    console.print(f"  Internal report: {result.internal_report_path}")
    console.print(f"  Internal report markdown: {result.internal_report_md_path}")
    if result.model_hypotheses_path:
        console.print(f"  Model hypotheses: {result.model_hypotheses_path}")
    if result.model_transcript_path:
        console.print(f"  Model transcript: {result.model_transcript_path}")
    console.print(f"  Researcher model: {researcher_model}")
    console.print(f"  Skeptic model: {skeptic_model}")
    console.print(f"  Materialized tools: {materialize_tools}")
    console.print(f"  Consensus hypotheses: {result.consensus_count}")
    console.print(f"  Rejected hypotheses: {result.rejected_count}")
    console.print(f"  Validated findings: {result.validated_count}")
    if result.verification_package_paths:
        console.print("  Verification packages:")
        for path in result.verification_package_paths:
            console.print(f"    - {path}")


# ============================================
# Daemon Command
# ============================================


@app.command("daemon")
def daemon():
    """Start autonomous audit daemon (queue processor)."""
    from src.daemon import AuditDaemon

    console.print("[cyan]Starting daemon in queue processor mode...[/cyan]")
    daemon_instance = AuditDaemon(verbose=True)
    try:
        asyncio.run(daemon_instance.run_loop())
    except KeyboardInterrupt:
        console.print("\n[yellow]Daemon stopped[/yellow]")


# ============================================
# Telegram Bot Command
# ============================================


@app.command("bot")
def bot():
    """
    Start Telegram bot for interactive PoC verification.

    The bot receives callback queries from 'Run PoC' buttons
    sent with audit reports. When clicked, triggers PoC
    verification for CRITICAL findings.

    Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars.
    """
    from src.config import settings
    from src.telegram_bot import run_bot

    if not settings.telegram_bot_token:
        console.print("[red]TELEGRAM_BOT_TOKEN not configured[/red]")
        console.print("Set it in .env file or environment")
        raise typer.Exit(1)

    if not settings.telegram_chat_id:
        console.print("[yellow]Warning: TELEGRAM_CHAT_ID not configured[/yellow]")
        console.print("Bot will not know where to send reports")

    console.print("[cyan]Starting Telegram bot (polling mode)...[/cyan]")
    console.print("Press Ctrl+C to stop")

    try:
        asyncio.run(run_bot())
    except KeyboardInterrupt:
        console.print("\n[yellow]Bot stopped[/yellow]")


# ============================================
# RAG Commands
# ============================================

rag_app = typer.Typer(help="RAG operations")
app.add_typer(rag_app, name="rag")


@rag_app.command("init")
def rag_init():
    """Initialize RAG database."""
    from src.rag.db import init_lancedb

    console.print("[cyan]Initializing RAG database...[/cyan]")
    asyncio.run(init_lancedb())
    console.print("[green]RAG database initialized[/green]")


@rag_app.command("ingest")
def rag_ingest(
    limit: Annotated[int, typer.Option("--limit", "-n")] = 0,
):
    """Ingest exploit documents into RAG."""
    from src.config import RAGConfig
    from src.rag.db import ingest_exploits
    from src.rag.parser import parse_defihacklabs_directory

    defihacklabs_path = RAGConfig.defihacklabs_path
    if not defihacklabs_path.exists():
        console.print(f"[red]DeFiHackLabs directory not found: {defihacklabs_path}[/red]")
        console.print(
            "Clone it with: git clone https://github.com/SunWeb3Sec/DeFiHackLabs data/DeFiHackLabs"
        )
        raise typer.Exit(1)

    console.print(f"[cyan]Parsing exploits from {defihacklabs_path}...[/cyan]")
    exploits = parse_defihacklabs_directory(defihacklabs_path, limit=limit or None)
    console.print(f"[cyan]Parsed {len(exploits)} exploits[/cyan]")

    console.print("[cyan]Ingesting into RAG database...[/cyan]")
    count = asyncio.run(ingest_exploits(exploits))
    console.print(f"[green]Ingested {count} exploits[/green]")


@rag_app.command("search")
def rag_search(
    query: Annotated[str, typer.Argument(help="Search query")],
    top_k: Annotated[int, typer.Option("--top-k", "-k")] = 5,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Search RAG database."""
    from src.rag.search import hybrid_search

    console.print(f"[cyan]Searching for: {query}[/cyan]")

    results = asyncio.run(hybrid_search(query, limit=top_k))

    if not results:
        console.print("[yellow]No results found[/yellow]")
        return

    if json_output:
        data = [
            {
                "id": r.id,
                "name": r.name,
                "date": r.date,
                "chain": r.chain,
                "loss_usd": r.loss_usd,
                "attack_type": r.attack_type,
                "summary": r.summary[:200],
            }
            for r in results
        ]
        console.print_json(json.dumps(data))
        return

    for i, r in enumerate(results, 1):
        loss = f"${r.loss_usd / 1_000_000:.2f}M" if r.loss_usd else "Unknown"
        score_color = "green" if r.score > 0.01 else "yellow"
        console.print(
            f"\n[cyan]{i}. {r.name}[/cyan] ({r.date}) [{score_color}]score: {r.score:.4f}[/{score_color}]"
        )
        console.print(f"   Chain: {r.chain} | Loss: {loss} | Type: {r.attack_type}")
        console.print(f"   {r.summary[:200]}...")


# ============================================
# Discovery Commands
# ============================================

discovery_app = typer.Typer(help="Contract discovery operations")
app.add_typer(discovery_app, name="discovery")


@discovery_app.command("scan")
def discovery_scan(
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            "-m",
            help="simulate (test data), light (scraping), or full (Rust extractor)",
        ),
    ] = "simulate",
    live: Annotated[
        bool,
        typer.Option(
            "--live",
            help="Allow real block-explorer scraping (light/full). Authorized/testnet use only.",
        ),
    ] = False,
    enqueue: Annotated[
        bool,
        typer.Option("--enqueue", help="Also add discovered contracts to the audit queue"),
    ] = False,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 10_000,
    min_balance: Annotated[int, typer.Option("--min-balance")] = 100_000,
    snapshot_block: Annotated[int | None, typer.Option("--block")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """
    Discover high-value contracts. Defaults to the harmless 'simulate' mode.

    Modes:
      simulate: Loads built-in test data (no network access). DEFAULT.
      light:    Scrapes a block explorer (no node required). Requires --live.
      full:     Uses the Rust extractor with a local node. Requires --live.

    Live block-explorer scraping must respect each provider's ToS and rate
    limits, and is intended for authorized assessments or testnet only.
    Discovery only records results unless --enqueue is passed.
    """
    from src.discovery import DiscoveryCriteria, DiscoveryOrchestrator

    if mode not in {"simulate", "light", "full"}:
        console.print("[red]Invalid mode: use 'simulate', 'light', or 'full'[/red]")
        raise typer.Exit(1)

    # Gate live scraping behind an explicit opt-in flag; fall back to simulate.
    if mode in {"light", "full"} and not live:
        console.print(
            f"[yellow]Live '{mode}' scanning requires --live and is for "
            "authorized/testnet use only.[/yellow]"
        )
        console.print("[yellow]Falling back to 'simulate' mode (test data).[/yellow]")
        mode = "simulate"

    console.print(f"[cyan]Starting discovery scan on {chain.upper()}...[/cyan]")
    console.print(f"  Mode: {mode}")
    console.print(f"  Enqueue: {enqueue}")
    console.print(f"  Limit: {limit:,}")
    console.print(f"  Min balance: ${min_balance:,}")
    if snapshot_block is not None:
        console.print(f"  Snapshot block: {snapshot_block}")
    console.print()

    orchestrator = DiscoveryOrchestrator()

    if mode == "simulate":
        result = asyncio.run(orchestrator.simulate(chain, enqueue=enqueue))
    else:
        criteria = DiscoveryCriteria(
            min_balance_usd=min_balance,
            limit=limit,
        )
        result = asyncio.run(
            orchestrator.discover(
                chain,
                mode,  # type: ignore[arg-type]
                criteria,
                snapshot_block=snapshot_block,
                enqueue=enqueue,
            )
        )

    if json_output:
        data = {
            "chain": result.chain,
            "mode": result.mode,
            "contracts_found": result.contracts_found,
            "contracts_queued": result.contracts_added_to_queue,
            "total_value_usd": result.total_value_usd,
            "duration_seconds": result.duration_seconds,
            "errors": result.errors,
        }
        console.print_json(json.dumps(data))
        return

    console.print()
    console.print("[green]Discovery complete![/green]")
    console.print(f"  Contracts found: {result.contracts_found}")
    console.print(f"  Added to queue: {result.contracts_added_to_queue}")
    console.print(f"  Total value: ${result.total_value_usd / 1_000_000:.2f}M")
    console.print(f"  Duration: {result.duration_seconds:.1f}s")
    if not enqueue:
        console.print(
            "\n[yellow]Results recorded only. Use 'audit queue add' to enqueue "
            "for audit, or re-run with --enqueue.[/yellow]"
        )

    if result.errors:
        console.print(f"\n[yellow]Errors ({len(result.errors)}):[/yellow]")
        for error in result.errors[:5]:
            console.print(f"  - {error}")
        if len(result.errors) > 5:
            console.print(f"  ... and {len(result.errors) - 5} more")


@discovery_app.command("prices")
def discovery_prices(
    chains: Annotated[str, typer.Option("--chains", "-c")] = "eth,bsc,arbitrum,base,polygon",
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Show current native token prices from DeFiLlama."""
    from src.price import PriceService

    chain_list = [c.strip() for c in chains.split(",")]

    console.print("[cyan]Fetching prices from DeFiLlama...[/cyan]")

    service = PriceService()
    prices = asyncio.run(service.get_native_prices(chain_list))

    if json_output:
        console.print_json(json.dumps(prices))
        return

    table = Table(title="Native Token Prices")
    table.add_column("Chain", style="cyan")
    table.add_column("Price (USD)", style="green", justify="right")

    for chain in chain_list:
        price = prices.get(chain.lower(), 0)
        table.add_row(chain.upper(), f"${price:,.2f}")

    console.print(table)


@discovery_app.command("clone-families")
def discovery_clone_families(
    min_size: Annotated[int, typer.Option("--min-size", min=2)] = 2,
    limit: Annotated[int, typer.Option("--limit", "-n", min=1)] = 20,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
):
    """Group discovered contracts by identical runtime bytecode hash."""
    with get_db() as db:
        families = db.get_clone_families(min_size=min_size, limit=limit)

    if json_output:
        console.print_json(
            json.dumps([family.model_dump(by_alias=True, mode="json") for family in families])
        )
        return

    if not families:
        console.print("[yellow]No clone families found[/yellow]")
        return

    table = Table(title="Clone Families")
    table.add_column("Bytecode Hash", style="cyan", no_wrap=True)
    table.add_column("Members", justify="right")
    table.add_column("Chains", style="blue")
    table.add_column("Total Value USD", style="green", justify="right")
    table.add_column("Proxy Count", justify="right")
    table.add_column("Representative", style="magenta", no_wrap=True)

    for family in families:
        table.add_row(
            family.bytecode_hash[:18] + "...",
            str(len(family.members)),
            ",".join(chain.value for chain in family.chains),
            f"${family.total_value_usd:,.0f}",
            str(family.proxy_count),
            family.representative_address[:10] + "..." + family.representative_address[-6:],
        )

    console.print(table)


@discovery_app.command("simulate")
def discovery_simulate(
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    enqueue: Annotated[
        bool,
        typer.Option("--enqueue", help="Also add test contracts to the audit queue"),
    ] = False,
):
    """Add built-in test contracts for development/testing (no network access)."""
    from src.discovery import DiscoveryOrchestrator

    console.print(f"[cyan]Adding test contracts for {chain.upper()}...[/cyan]")

    orchestrator = DiscoveryOrchestrator()
    result = asyncio.run(orchestrator.simulate(chain, enqueue=enqueue))

    console.print()
    console.print("[green]Test contracts added![/green]")
    console.print(f"  Contracts: {result.contracts_found}")
    console.print(f"  Queued: {result.contracts_added_to_queue}")
    console.print(f"  Total value: ${result.total_value_usd / 1_000_000:.2f}M")
    console.print()
    if enqueue:
        console.print("[yellow]Run 'audit queue list' to see queued contracts[/yellow]")
    else:
        console.print(
            "[yellow]Recorded only. Re-run with --enqueue to add to the audit queue.[/yellow]"
        )


# ============================================
# Parallel Audit Command
# ============================================


@app.command("parallel-audit")
def parallel_audit(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    max_retries: Annotated[int, typer.Option("--max-retries")] = 3,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    timeout: Annotated[
        int, typer.Option("--timeout", help="Timeout per instance in seconds")
    ] = 1200,
):
    """
    Run parallel audit with multiple Claude instances.

    Spawns multiple Claude Code instances with /ultrathink to audit the same contract.
    Each instance generates an independent report.

    Prerequisites: Run triage, resolve, decompile stages first.
    """
    from src.stages.parallel_audit import (
        PreAuditResult,
        run_parallel_audit,
    )
    from src.stages.resolve import resolve_contract
    from src.stages.triage import triage_contract

    chain_enum = Chain(chain)

    # Run triage
    console.print(f"[cyan]Triaging {address} on {chain}...[/cyan]")
    triage_result = asyncio.run(triage_contract(address, chain_enum))

    if triage_result.skip_reason:
        console.print(f"[red]Triage failed: {triage_result.skip_reason}[/red]")
        raise typer.Exit(1)

    # Run resolve
    console.print("[cyan]Resolving contract...[/cyan]")
    resolved = asyncio.run(resolve_contract(address, chain_enum))
    console.print(f"  Proxy: {resolved.is_proxy} ({resolved.proxy_type or 'none'})")
    console.print(f"  Resolved: {resolved.resolved_address}")

    # Check for decompiled code (use original address, not resolved)
    audit_dir = get_audit_dir(chain, address)
    decompile_dir = audit_dir / "decompiled"

    if not decompile_dir.exists():
        console.print(f"[red]No decompiled data at {decompile_dir}[/red]")
        console.print("[yellow]Run: audit decompile {address} --chain {chain}[/yellow]")
        raise typer.Exit(1)

    # Check for decompiled file
    dedaub_file = decompile_dir / "dedaub.sol"

    if not dedaub_file.exists():
        console.print("[red]No dedaub.sol found[/red]")
        raise typer.Exit(1)

    # Build pre-audit result
    pre_audit = PreAuditResult(
        address=address.lower(),
        chain=chain,
        balance_usd=triage_result.balance_usd or 0,
        is_proxy=resolved.is_proxy,
        proxy_type=resolved.proxy_type.value if resolved.proxy_type else None,
        resolved_address=resolved.resolved_address,
        decompile_dir=str(decompile_dir),
        dedaub_file=str(dedaub_file) if dedaub_file.exists() else None,
        passed=True,
    )

    console.print("\n[green]Starting parallel audit...[/green]")

    # Run parallel audit (instance count from AuditConfig.audit_prompts)
    result = asyncio.run(
        run_parallel_audit(
            pre_audit,
            max_retries=max_retries,
            verbose=verbose,
            timeout_ms=timeout * 1000,
        )
    )

    # Show results
    total = result.success_count + result.fail_count
    if result.all_failed:
        console.print("[red]All instances failed![/red]")
        raise typer.Exit(1)

    console.print(f"\n[green]Success: {result.success_count}/{total}[/green]")
    console.print("[cyan]Reports:[/cyan]")
    for path in result.report_paths:
        console.print(f"  {path}")

    if result.fail_count > 0:
        console.print(f"\n[yellow]Failed instances: {result.fail_count}[/yellow]")
        for r in result.instance_results:
            if not r.success:
                console.print(f"  Instance {r.instance_id}: {r.error}")


# ============================================
# Verify Command
# ============================================


@app.command("verify")
def verify(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
):
    """
    Run PoC verification for pending findings.

    Reads findings from the last audit report and runs PoC verification
    for CRITICAL findings with high confidence.
    """
    from src.stages.verify import run_verify
    from src.telegram_bot import _load_pending_poc

    # First try to find in pending_poc storage
    pending = _load_pending_poc()
    matching = None

    for key, data in pending.items():
        if data.address.lower() == address.lower() and data.chain.value == chain.lower():
            matching = (key, data)
            break

    if not matching:
        # Try to load from report
        audit_dir = get_audit_dir(chain, address)
        report_path = audit_dir / "reports" / "final.md"

        if not report_path.exists():
            console.print(f"[red]No pending PoC or report found for {address}[/red]")
            raise typer.Exit(1)

        console.print("[yellow]No pending PoC found, loading from report...[/yellow]")
        console.print("[yellow]Note: Need to parse findings from report (not implemented)[/yellow]")
        raise typer.Exit(1)

    key, data = matching
    console.print(f"[cyan]Running PoC verification for {data.address}...[/cyan]")

    critical_findings = [
        f for f in data.findings if f.severity.value == "critical" and f.confidence >= 0.6
    ]
    console.print(f"  Found {len(critical_findings)} CRITICAL findings to verify")

    if not critical_findings:
        console.print("[yellow]No CRITICAL findings with high confidence[/yellow]")
        raise typer.Exit(0)

    # Run verification
    updated_findings = asyncio.run(
        run_verify(
            data.address,
            data.chain,
            data.findings,
            data.decompiled_code,
        )
    )

    # Show results
    verified_count = sum(1 for f in updated_findings if f.verified)
    console.print()

    if verified_count > 0:
        console.print(f"[red]VERIFIED: {verified_count} vulnerabilities confirmed![/red]")
    else:
        console.print("[green]No vulnerabilities verified (may be false positives)[/green]")

    # Remove from pending
    del pending[key]
    from src.telegram_bot import _save_pending_poc

    _save_pending_poc(pending)
    console.print("\n[dim]Removed from pending queue[/dim]")


@app.command("restore-poc")
def restore_poc(
    address: Annotated[str, typer.Argument(help="Contract address")],
    chain: Annotated[str, typer.Option("--chain", "-c")] = "eth",
    send_telegram: Annotated[bool, typer.Option("--send", "-s")] = True,
):
    """
    Restore pending PoC from existing audit report.

    Reads findings from final.md, creates pending_poc entry,
    and optionally sends new Telegram message with Run PoC button.
    """
    from datetime import datetime

    from src.models import AuditReport, AuditResult, FindingsCount, Severity
    from src.stages.parallel_audit import aggregate_findings
    from src.telegram_bot import (
        PendingPoC,
        _load_pending_poc,
        _save_pending_poc,
        send_initial_report,
    )

    # Find audit directory
    audit_dir = get_audit_dir(chain, address)
    reports_dir = audit_dir / "reports"

    if not reports_dir.exists():
        console.print(f"[red]No reports found for {address}[/red]")
        raise typer.Exit(1)

    # Find all audit_*.md files
    audit_reports = sorted(reports_dir.glob("audit_*.md"))

    if not audit_reports:
        console.print("[red]No audit_*.md files found[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Found {len(audit_reports)} audit reports[/cyan]")

    # Aggregate findings from all reports
    findings = aggregate_findings([str(p) for p in audit_reports])

    if not findings:
        console.print("[yellow]No findings parsed from reports[/yellow]")
        console.print("[dim]Reports may not contain JSON findings blocks[/dim]")
        raise typer.Exit(1)

    console.print(f"[cyan]Parsed {len(findings)} findings[/cyan]")

    # Check for CRITICAL findings
    critical_findings = [
        f for f in findings if f.severity == Severity.CRITICAL and f.confidence >= 0.6
    ]

    if not critical_findings:
        console.print("[yellow]No CRITICAL findings with high confidence[/yellow]")
        raise typer.Exit(0)

    console.print(f"[green]Found {len(critical_findings)} CRITICAL findings[/green]")

    # Also check implementation directory for proxy
    impl_dir = None
    for d in audit_dir.parent.iterdir():
        if (
            d.is_dir()
            and d.name.startswith(f"{chain}_")
            and d.name != audit_dir.name
            and (d / "decompiled" / "dedaub.sol").exists()
        ):
            impl_dir = d / "decompiled"
            break

    # Try multiple locations
    possible_paths = [
        audit_dir / "decompiled" / "dedaub.sol",
        audit_dir / "decompiled" / "implementation.sol",
    ]

    # Add implementation directory if found
    if impl_dir:
        possible_paths.insert(0, impl_dir / "dedaub.sol")

    decompiled_code = ""
    for path in possible_paths:
        if path.exists():
            decompiled_code = path.read_text()
            console.print(f"[dim]Using decompiled code from: {path}[/dim]")
            break

    if not decompiled_code:
        console.print("[yellow]Warning: No decompiled code found[/yellow]")

    # Build findings count
    findings_count = FindingsCount(
        critical=sum(1 for f in findings if f.severity.value == "critical"),
        high=sum(1 for f in findings if f.severity.value == "high"),
        medium=sum(1 for f in findings if f.severity.value == "medium"),
        low=sum(1 for f in findings if f.severity.value == "low"),
        info=sum(1 for f in findings if f.severity.value == "info"),
    )

    # Build report for Telegram
    report = AuditReport(
        address=address.lower(),
        chain=Chain(chain),
        startedAt=datetime.now(UTC),
        completedAt=datetime.now(UTC),
        status=AuditResult.VULNERABLE,
        findings=findings,
        findingsCount=findings_count,
        ragContextUsed=False,
    )

    report_path = str(reports_dir / "final.md")

    if send_telegram:
        console.print("[cyan]Sending Telegram message with PoC button...[/cyan]")

        success, msg_id = asyncio.run(send_initial_report(report, decompiled_code, report_path))

        if success:
            console.print(f"[green]Telegram message sent (msg_id={msg_id})[/green]")
            console.print("[cyan]Now start the bot and click the button:[/cyan]")
            console.print("  uv run python cli/main.py bot")
        else:
            console.print("[red]Failed to send Telegram message[/red]")
    else:
        # Just create pending_poc without sending
        pending = _load_pending_poc()
        key = f"manual:{address.lower()}"
        pending[key] = PendingPoC(
            address=address.lower(),
            chain=Chain(chain),
            findings=findings,
            decompiled_code=decompiled_code,
            report_path=report_path,
            created_at=datetime.now(UTC),
        )
        _save_pending_poc(pending)
        console.print(f"[green]Created pending_poc entry: {key}[/green]")
        console.print("[cyan]Run 'audit verify' to process[/cyan]")


# ============================================
# Main Entry Point
# ============================================

if __name__ == "__main__":
    app()
