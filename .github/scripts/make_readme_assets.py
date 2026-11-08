"""Regenerate the README screenshots in .github/assets/.

Each screenshot shows a question, the vulnflow `explore` call the skill makes
for it, and the real result on a full NVD build. Run it from a project that has
vulnflow installed and data/complete_library.parquet built (see SKILL.md):

    uv run --with rich python <path-to-VulnAnalyst>/.github/scripts/make_readme_assets.py

Also prints the figures README.md quotes.
"""

from __future__ import annotations

import io
from datetime import date
from pathlib import Path

import numpy as np
from rich import box
from rich.console import Console, RenderableType
from rich.measure import Measurement
from rich.table import Table
from rich.text import Text

from vulnflow import VulnDataset
from vulnflow.helpers import explore

ASSETS = Path(__file__).resolve().parent.parent / "assets"


def recording_console(width: int = 104) -> Console:
    return Console(
        record=True,
        width=width,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
    )


def save_svg(name: str, title: str, *renderables: RenderableType) -> None:
    # Size the terminal to the widest block so nothing wraps
    wide = recording_console(300)
    width = max(Measurement.get(wide, wide.options, r).maximum for r in renderables)
    console = recording_console(max(width, 72))
    for renderable in renderables:
        console.print(renderable)
    console.save_svg(str(ASSETS / name), title=title)


def ask(question: str, call: str) -> list[RenderableType]:
    """The prompt line and the explore call the skill runs for it."""
    return [
        Text.assemble(("> ", "bold"), (question, "bold")),
        Text.assemble(("  explore.", "dim"), (call, "cyan")),
        Text(""),
    ]


def yes_no(flag: object) -> Text:
    return Text("yes", style="bold red") if flag is True else Text("no", style="dim")


# --------------------------------------------------------------- patch_first.svg


def make_patch_first(ds: VulnDataset) -> None:
    rp = explore.risk_priority(ds, limit=10)
    table = Table(box=box.ROUNDED, header_style="bold cyan")
    for col, justify in [
        ("#", "right"),
        ("CVE", "left"),
        ("Vendor · product", "left"),
        ("CVSS", "right"),
        ("EPSS", "right"),
        ("KEV due", "left"),
        ("Ransomware", "left"),
    ]:
        table.add_column(col, justify=justify, no_wrap=True)  # type: ignore[arg-type]
    overdue = 0
    for i, row in enumerate(rp["top_urgent"], 1):
        cve = explore.lookup(ds, row["cve_id"]) or {}
        due = str(cve.get("kev_due_date") or "")[:10]
        overdue += bool(due) and date.fromisoformat(due) < date.today()
        table.add_row(
            str(i),
            Text(row["cve_id"], style="magenta"),
            f"{cve.get('kev_vendor')} · {cve.get('kev_product')}",
            f"{row['cvss_score']:.1f}",
            f"{row['epss']:.5f}",
            due,
            yes_no(cve.get("kev_ransomware")),
        )
    q = rp["quadrants"]
    footer = Text.assemble(
        (f"{overdue} of 10", "bold red"),
        " are past their KEV due date.\n",
        (f"{q['critical_exploited']:,}", "bold"),
        " high or critical CVEs in all are in KEV or have EPSS above 0.7.",
    )
    save_svg(
        "patch_first.svg",
        "VulnAnalyst · what should we patch first?",
        *ask("What should we patch first? Give me the top 10.", "risk_priority(ds, limit=10)"),
        table,
        footer,
    )
    print(f"patch_first: quadrants={q}, overdue={overdue}/10")


# ----------------------------------------------------------------- log4shell.svg


def make_log4shell(ds: VulnDataset) -> None:
    cve = explore.lookup(ds, "CVE-2021-44228") or {}
    card = Table.grid(padding=(0, 2))
    card.add_column(style="dim", no_wrap=True)
    card.add_column()
    rows = [
        ("Product", f"{cve.get('kev_vendor')} {cve.get('kev_product')}"),
        ("Weakness", f"{cve.get('cwe_id')} · {cve.get('cwe_name')}"),
        (
            "CVSS",
            Text.assemble(
                (f"{cve.get('cvss_version')} {cve.get('cvss_base_score'):.1f} ", "bold red"),
                (str(cve.get("cvss_vector_string")), "dim"),
            ),
        ),
        (
            "EPSS",
            Text.assemble(
                (f"{cve.get('epss_probability'):.5f}", "bold red"),
                f"  ({cve.get('epss_percentile'):.0%} percentile)",
            ),
        ),
        ("In KEV since", str(cve.get("kev_date_added"))[:10]),
        ("Ransomware", yes_no(cve.get("kev_ransomware"))),
        ("NVD status", str(cve.get("nvd_status"))),
    ]
    for label, value in rows:
        card.add_row(label, value)
    save_svg(
        "log4shell.svg",
        "VulnAnalyst · CVE lookup",
        *ask("Tell me about CVE-2021-44228. How bad is it really?", 'lookup(ds, "CVE-2021-44228")'),
        card,
    )
    print(f"log4shell: {[(k, str(v)) for k, v in rows]}")


# ---------------------------------------------------------------- ransomware.svg


def make_ransomware(ds: VulnDataset) -> None:
    kev = explore.search(
        ds, is_kev=True, limit=100_000, columns=["cve_id", "kev_vendor", "kev_ransomware"]
    )
    total = len(kev)
    by_vendor: dict[str, list[int]] = {}
    for row in kev:
        counts = by_vendor.setdefault(str(row["kev_vendor"]), [0, 0])
        counts[0] += 1
        counts[1] += row["kev_ransomware"] is True
    ransom = sum(c[1] for c in by_vendor.values())
    top = sorted(by_vendor.items(), key=lambda kv: -kv[1][1])[:8]

    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Vendor", no_wrap=True)
    table.add_column("KEV entries", justify="right")
    table.add_column("Ransomware", justify="right")
    table.add_column("Share", justify="right")
    for vendor, (n, r) in top:
        share = r / n
        table.add_row(
            vendor, f"{n:,}", f"{r:,}", Text(f"{share:.0%}", style="bold red" if share >= 0.5 else "")
        )
    footer = Text.assemble(
        (f"{ransom:,}", "bold red"), f" of {total:,} KEV entries ({ransom / total:.0%}) are linked to ransomware"
    )
    save_svg(
        "ransomware.svg",
        "VulnAnalyst · ransomware in KEV",
        *ask(
            "How many known exploited vulnerabilities are linked to ransomware, and which vendors dominate?",
            "search(ds, is_kev=True, columns=[...])",
        ),
        table,
        footer,
    )
    print(f"ransomware: {ransom}/{total}, top={top[:3]}")


# --------------------------------------------------------------------- trend.svg


def make_trend(ds: VulnDataset) -> None:
    # Same raw-column path SKILL.md describes; v3 only, so scores are comparable
    published = np.asarray(ds.get_column("nvd_published_at"), dtype="datetime64[Y]")
    years = published.astype("int64") + 1970
    version = ds.get_column("cvss_version").astype(str)
    v3 = np.char.startswith(version, "3")
    crit_net = (
        v3
        & (ds.get_column("cvss_base_severity") == "CRITICAL")
        & (ds.get_column("cvss_attack_vector") == "NETWORK")
    )
    this_year = date.today().year
    span = range(this_year - 10, this_year + 1)
    counts = {y: int(np.sum(crit_net & (years == y))) for y in span}
    shares = {y: counts[y] / max(int(np.sum(v3 & (years == y))), 1) for y in span}
    peak = max(counts.values())

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", pad_edge=False)
    table.add_column("Year", no_wrap=True)
    table.add_column("Critical + network", justify="right")
    table.add_column("of v3", justify="right", style="dim")
    table.add_column("", no_wrap=True)
    for y in span:
        bar = "█" * max(1, round(40 * counts[y] / peak))
        label = f"{y}*" if y == this_year else str(y)
        table.add_row(label, f"{counts[y]:,}", f"{shares[y]:.0%}", Text(bar, style="red"))
    footer = Text(f"* {this_year} through {date.today():%d %B}", style="dim")
    save_svg(
        "trend.svg",
        "VulnAnalyst · critical network CVEs",
        *ask(
            "How has the number of critical, network-exploitable CVEs changed over the last 10 years?",
            'search / raw columns: cvss_attack_vector == "NETWORK"',
        ),
        table,
        footer,
    )
    print(f"trend: {counts}, shares={ {y: round(s, 3) for y, s in shares.items()} }")


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    ds = explore.load()
    print(f"library: {len(ds):,} CVEs")
    make_patch_first(ds)
    make_log4shell(ds)
    make_ransomware(ds)
    make_trend(ds)


if __name__ == "__main__":
    main()
