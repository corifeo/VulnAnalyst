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

## Contents

| File | Purpose |
|------|---------|
| `SKILL.md` | Workflow: check data, query with `vulnflow.helpers.explore`, interpret |
| `references/domain.md` | CVSS, EPSS, KEV, SSVC, CVD model, prioritization |
| `references/recipes.md` | Build, query, export and pipeline code patterns |

## License

MIT. NVD, EPSS and KEV data carry their own terms; see the [vulnflow README](https://github.com/corifeo/VulnFlow#data-sources-and-notices).
