# VulnAnalyst

A Claude skill that answers vulnerability questions like an analyst, using [vulnflow](https://github.com/corifeo/VulnFlow) data: NVD, CVSS, EPSS, CISA KEV, CWE, CPE and CVD state.

Ask "what should we patch first?", "which vendors had the most critical CVEs in 2025?" or "what is CVE-2021-44228?" and it builds or reuses a local NVD cache, queries it, and answers with severity, likelihood and exploitation combined.

## Requirements

- A project that uses [uv](https://docs.astral.sh/uv/) with vulnflow installed:

```bash
uv add git+https://github.com/corifeo/vulnflow
```

- Run Claude from that project's root. The cache is written to `data/complete_library.parquet` there. The first full build downloads every NVD yearly feed.

## Install

Claude Code, for all projects:

```bash
git clone https://github.com/corifeo/VulnAnalyst ~/.claude/skills/vuln-analyst
```

For one project only, clone into `.claude/skills/vuln-analyst` inside that project instead.

## Examples

Real answers from a fresh Claude Code session with only this skill installed, on a full NVD build (433,329 CVEs, built 2026-11-08 in about 2 minutes). Every figure was cross-checked against direct parquet queries. Answers are condensed.

**"What should we patch first? Give me the top 10."** Uses `risk_priority`.

> All ten are in CISA KEV, have CVSS 10.0, and have EPSS above 0.99:
>
> | # | CVE | Product | Ransomware |
> |---|-----|---------|------------|
> | 1 | CVE-2024-3400 | Palo Alto PAN-OS GlobalProtect | Yes |
> | 2 | CVE-2021-44228 | Apache Log4j2 | Yes |
> | 3 | CVE-2019-11510 | Ivanti Pulse Connect Secure | Yes |
> | 4 | CVE-2021-34473 | Microsoft Exchange (ProxyShell) | Yes |
> | … | | | |
>
> Eight of ten are years past their KEV due date: if still deployed, assume compromise and hunt, don't just patch.

**"Tell me about CVE-2021-44228. How bad is it really?"** Uses `lookup`.

> CVSS 3.1 10.0 (`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`), EPSS 0.99999, in KEV since 2021-12-10, used by ransomware. The 10.0 is earned. Today's risk is leftover copies in vendor appliances and old Java services.

**"How many known exploited vulnerabilities are linked to ransomware, and which vendors dominate?"** Uses `exploitation` and the KEV columns.

> 361 of 1,783 KEV entries (20%). Microsoft leads with 117. By share, QNAP (82% of its KEV entries) and SonicWall (62%) are the most ransomware-prone.

**"Which vendors had the most critical CVEs published in 2025?"**

> 6,651 critical CVEs. The top of the list is bulk-reported PHP projects and routers: phpgurukul 319, campcodes 243, fabian 172, code-projects 134, dlink 105. Among major vendors, Apple has 95 and Microsoft 54. About 26% have no CPE vendor yet.

**"How has the number of critical, network-exploitable CVEs changed over the last 10 years?"**

> CVSS v3 critical plus network rose from 2,107 (2017) to 5,993 (2025), with 9,333 in 2026 through November. The share stays at 12–18% of v3-scored CVEs, so the growth tracks overall CVE volume.

## Contents

| File | Purpose |
|------|---------|
| `SKILL.md` | Workflow: check data, query with `vulnflow.helpers.explore`, interpret |
| `references/domain.md` | CVSS, EPSS, KEV, SSVC, CVD model, prioritization |
| `references/recipes.md` | Build, query, export and pipeline code patterns |

## License

MIT. NVD, EPSS and KEV data carry their own terms; see the [vulnflow README](https://github.com/corifeo/VulnFlow#data-sources-and-notices).
