import argparse
from rich.console import Console
from rich.table import Table

from blackscope.banner import show_banner
from blackscope.display import print_dashboard
from blackscope.scanner import scan_target

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="BlackScope OSINT - Domain Intelligence Scanner"
    )
    parser.add_argument("target", help="Domain to scan, example: example.com")
    args = parser.parse_args()

    show_banner()
    console.print(f"[cyan]Scanning target:[/cyan] {args.target}")

    results = scan_target(args.target)
    print_dashboard(results)

    console.rule("[bold red]Scan Results")

    print_dns(results)
    print_whois(results)
    print_ssl(results)
    print_headers(results)
    print_ip_intel(results)
    print_technologies(results)
    print_risk_assessment(results)


def make_table(title, columns):
    table = Table(title=title, show_lines=True)
    for column in columns:
        table.add_column(column)
    return table


def print_dns(results):
    table = make_table("DNS Records", ["Type", "Value"])
    for record_type, values in results.get("dns", {}).items():
        if values:
            for value in values:
                table.add_row(record_type, value)
        else:
            table.add_row(record_type, "No records found")
    console.print(table)


def print_whois(results):
    whois_data = results.get("whois", {})

    table = make_table("WHOIS Information", ["Field", "Value"])

    if "error" in whois_data:
        table.add_row("Error", whois_data["error"])
    else:
        for key in [
            "registrar",
            "creation_date",
            "expiration_date",
            "updated_date",
            "organization",
            "country",
        ]:
            table.add_row(key.replace("_", " ").title(), str(whois_data.get(key)))

        table.add_row("Name Servers", "\n".join(whois_data.get("name_servers", [])) or "None")
        table.add_row("Emails", "\n".join(whois_data.get("emails", [])) or "None")

    console.print(table)


def print_ssl(results):
    ssl_data = results.get("ssl", {})

    table = make_table("SSL Certificate", ["Field", "Value"])

    if ssl_data.get("valid"):
        for key in [
            "hostname",
            "subject",
            "issuer",
            "organization",
            "version",
            "serial_number",
            "valid_from",
            "valid_until",
            "days_remaining",
        ]:
            table.add_row(key.replace("_", " ").title(), str(ssl_data.get(key)))
    else:
        table.add_row("Error", str(ssl_data.get("error")))

    console.print(table)


def print_headers(results):
    header_data = results.get("headers", {})

    table = make_table("HTTP Security Headers", ["Header", "Status", "Value"])

    if "error" in header_data:
        table.add_row("Error", "Failed", header_data["error"])
    else:
        for header_name, info in header_data.get("headers", {}).items():
            if info.get("present"):
                value = info.get("value") or ""
                if len(value) > 80:
                    value = value[:77] + "..."
                table.add_row(header_name, "[green]Present[/green]", value)
            else:
                table.add_row(header_name, "[red]Missing[/red]", "Missing")

    console.print(table)


def print_ip_intel(results):
    ip_data = results.get("ip_intel", {})

    table = make_table("IP Intelligence", ["Field", "Value"])

    if "error" in ip_data:
        table.add_row("Error", ip_data["error"])
    else:
        for key in [
            "ip",
            "reverse_dns",
            "asn",
            "asn_cidr",
            "asn_country",
            "asn_description",
            "network_name",
            "network_type",
            "network_country",
            "network_start",
            "network_end",
        ]:
            table.add_row(key.replace("_", " ").title(), str(ip_data.get(key)))

    console.print(table)


def print_technologies(results):
    tech_data = results.get("technologies", {})

    table = make_table("Technology Detection", ["Technology", "Confidence", "Evidence"])

    if "error" in tech_data:
        table.add_row("Error", "0%", tech_data["error"])
    else:
        detected = tech_data.get("detected", [])
        if not detected:
            table.add_row("None", "0%", "No technologies detected")
        else:
            for tech in detected:
                table.add_row(
                    str(tech.get("name")),
                    f"{tech.get('confidence')}%",
                    str(tech.get("evidence")),
                )

    console.print(table)


def print_risk_assessment(results):
    risk = results.get("risk_assessment", {})
    score = risk.get("score", 0)
    level = risk.get("risk_level", "UNKNOWN")

    table = make_table("BLACKSCOPE RISK ASSESSMENT", ["Category", "Details"])

    table.add_row("Overall Score", f"{score} / 100")
    table.add_row("Risk Level", level)
    table.add_row("Findings", "\n".join(f"✓ {x}" for x in risk.get("findings", [])) or "None")
    table.add_row("Warnings", "\n".join(f"⚠ {x}" for x in risk.get("warnings", [])) or "None")
    table.add_row("Scan Duration", f"{results.get('scan_duration')} seconds")

    console.print(table)


if __name__ == "__main__":
    main()