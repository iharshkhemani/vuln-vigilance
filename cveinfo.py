#!/usr/bin/env python3
import requests
import sys
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def get_nvd_data(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        "User-Agent": "cve-tool/1.0"  # required by NVD
    }
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    vuln = data.get("vulnerabilities", [])[0]["cve"]

    title = vuln.get("descriptions", [])[0]["value"]
    published = vuln.get("published")
    last_modified = vuln.get("lastModified")

    # Choose the best available CVSS metrics
    metrics = vuln.get("metrics", {})
    cvss_score = severity = None

    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]
        cvss_score = m["cvssData"]["baseScore"]
        severity = m.get("baseSeverity")
    elif "cvssMetricV30" in metrics:
        m = metrics["cvssMetricV30"][0]
        cvss_score = m["cvssData"]["baseScore"]
        severity = m.get("baseSeverity")
    elif "cvssMetricV2" in metrics:
        m = metrics["cvssMetricV2"][0]
        cvss_score = m["cvssData"]["baseScore"]
        severity = m.get("baseSeverity")

    return title, cvss_score, severity, published, last_modified


def get_epss_data(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    entry = data.get("data", [None])[0]
    if not entry:
        return None, None
    return entry.get("epss"), entry.get("percentile")


def main():
    if len(sys.argv) != 2:
        console.print(f"[red]Usage:[/red] {sys.argv[0]} <CVE-ID>")
        sys.exit(1)

    cve_id = sys.argv[1]
    try:
        title, cvss_score, severity, published, last_modified = get_nvd_data(cve_id)
        epss_score, epss_percentile = get_epss_data(cve_id)

        table = Table(title=f"CVE Information: {cve_id}", box=box.ROUNDED, show_lines=True)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        table.add_row("Title", title)
        table.add_row("Published Date", str(published))
        table.add_row("Last Modified", str(last_modified))
        table.add_row("CVSS Score", str(cvss_score))
        table.add_row("Severity", f"[bold red]{severity}[/bold red]" if severity in ["CRITICAL", "HIGH"] else severity)
        if epss_score:
            table.add_row("EPSS Score", str(epss_score))
            table.add_row("EPSS Percentile", str(epss_percentile))
        else:
            table.add_row("EPSS", "Not available")

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error fetching data:[/bold red] {e}")


if __name__ == "__main__":
    main()
