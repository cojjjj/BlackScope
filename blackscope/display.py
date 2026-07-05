from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_dashboard(results):
    risk = results.get("risk_assessment", {})
    score = risk.get("score", 0)
    level = risk.get("risk_level", "UNKNOWN")

    color = "green" if level == "LOW" else "yellow" if level == "MEDIUM" else "red"

    summary = Table.grid(padding=(0, 3))
    summary.add_column(style="cyan", justify="right")
    summary.add_column(style="white")

    summary.add_row("Target", str(results.get("target")))
    summary.add_row("IP", str(results.get("ip_address")))
    summary.add_row("Status", "[green]COMPLETE ✓[/green]")
    summary.add_row("Scan Time", f"{results.get('scan_duration')} seconds")
    summary.add_row("Risk Score", f"[{color}]{score}/100[/{color}]")
    summary.add_row("Risk Level", f"[{color}]{level}[/{color}]")

    modules = Table(title="MODULES", show_header=False, box=None)
    modules.add_column("Status", style="green")
    modules.add_column("Module", style="white")

    modules.add_row("✓", "DNS")
    modules.add_row("✓", "WHOIS")
    modules.add_row("✓", "SSL")
    modules.add_row("✓", "HEADERS")
    modules.add_row("✓", "IP INTEL")
    modules.add_row("✓", "RISK ENGINE")

    console.print("\n[bold red]██████████████████████████████████████████████[/bold red]")
    console.print("[bold white]                 BLACKSCOPE OSINT[/bold white]")
    console.print("[bold red]██████████████████████████████████████████████[/bold red]\n")

    console.print(
        Panel(
            summary,
            title="[bold red]SCAN SUMMARY[/bold red]",
            border_style="red",
            padding=(1, 4),
        )
    )

    console.print(modules)

    console.print("[bold red]██████████████████████████████████████████████[/bold red]\n")