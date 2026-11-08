# Vulnerability Analysis Recipes

## Explore Recipes

All explore recipes use `fmt="json"`. Import once:

```python
from vulnflow.helpers import explore
ds = explore.load()
```

### Data Readiness

```python
from vulnflow.helpers.explore import data_info
print(data_info(fmt="json"))
```

### Summary & Distributions

```python
print(explore.summary(ds, fmt="json"))
print(explore.describe_severity(ds, fmt="json"))
print(explore.describe_yearly(ds, fmt="json"))
print(explore.describe_monthly(ds, year=2024, fmt="json"))
print(explore.status_distribution(ds, fmt="json"))
```

### Filtered Severity Breakdown

```python
# By attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL). If it returns total 0, use Raw Column Filtering below
print(explore.describe_severity(ds, attack_vector="NETWORK", fmt="json"))

# By minimum CVSS score
print(explore.describe_severity(ds, min_score=9.0, fmt="json"))

# Combined filters
print(explore.describe_severity(ds, attack_vector="NETWORK", min_score=9.0, fmt="json"))
```

### Nested Column Inspection

```python
print(explore.describe_nested(ds, "cwes", "id", n=20, fmt="json"))
print(explore.describe_nested(ds, "cpes", "vendor", n=20, fmt="json"))
print(explore.describe_nested(ds, "cpes", "product", n=20, fmt="json"))
print(explore.describe_nested(ds, "cvss_scores", "source", fmt="json"))
```

### Search & Lookup

```python
print(explore.search(ds, severity="CRITICAL", limit=20, fmt="json"))
print(explore.search(ds, min_score=9.0, year=2024, limit=20, fmt="json"))
print(explore.search(ds, keyword="log4j", limit=20, fmt="json"))
print(explore.search(ds, cwe="CWE-89", severity="CRITICAL", limit=20, fmt="json"))
print(explore.search(ds, severity="CRITICAL", attack_vector="NETWORK", limit=20, fmt="json"))
print(explore.search(ds, is_kev=True, ransomware=True, limit=20, fmt="json"))
print(explore.search(ds, min_epss=0.5, vendor="microsoft", limit=20, fmt="json"))
print(explore.search(ds, status="awaiting", year=2026, limit=20, fmt="json"))  # status values are lowercase
print(explore.lookup(ds, "CVE-2021-44228", fmt="json"))
```

### Risk and Exploitation

```python
print(explore.risk_priority(ds, limit=20, fmt="json"))   # patch-first list
print(explore.exploitation(ds, fmt="json"))              # KEV + EPSS overview
print(explore.attack_surface(ds, fmt="json"))            # AV/AC/PR/UI distributions
print(explore.vendor_risk(ds, top_n=15, fmt="json"))     # riskiest vendors
print(explore.vendor_risk(ds, vendor="apache", fmt="json"))
print(explore.weakness_profile(ds, year=2025, top_n=15, fmt="json"))
```

### Raw Column Filtering

```python
import numpy as np
# cvss_attack_vector stores full names: NETWORK, ADJACENT_NETWORK/ADJACENT, LOCAL, PHYSICAL
av = ds.get_column("cvss_attack_vector")
sev = ds.get_column("cvss_base_severity")
mask = (av == "NETWORK") & (sev == "CRITICAL")
print(int(np.sum(mask)))
```

### Combined Queries (Minimize Turns)

```python
# Multiple queries, single load, single tool call
print(explore.summary(ds, fmt="json"))
print(explore.describe_severity(ds, fmt="json"))
print(explore.describe_yearly(ds, fmt="json"))
```

---

## Build & Rebuild Library

### Build Complete Library (All Years)

```python
from vulnflow.helpers import CacheBuilder
ds = CacheBuilder(include_modified=True, quiet=True).build()
ds.to_parquet("data/complete_library.parquet")
```

### Build Specific Years

```python
from vulnflow.helpers import CacheBuilder
from vulnflow.helpers import explore
ds = CacheBuilder(years=[2023, 2024, 2025], quiet=True).build()
ds.to_parquet("data/nvd_recent.parquet")
# explore.load() won't find this file on its own: pass the path
ds = explore.load("data/nvd_recent.parquet")
```

### Exclude Old Years

```python
from vulnflow.helpers import CacheBuilder
ds = CacheBuilder(exclude_years=[2002, 2003, 2004], quiet=True).build()
ds.to_parquet("data/complete_library.parquet")
```

### Quick Update (Modified Feed Only)

```python
from vulnflow.helpers import CacheBuilder
from vulnflow.dataset import VulnDataset
existing = VulnDataset.from_parquet("data/complete_library.parquet")
delta = CacheBuilder(modified_only=True, quiet=True).build()
merged = VulnDataset.merge([existing, delta])
merged.to_parquet("data/complete_library.parquet")
```

### Recent Feed Only (Fast Check)

```python
from vulnflow.helpers import CacheBuilder
ds = CacheBuilder(recent_only=True, quiet=True).build()
ds.to_parquet("data/nvd_recent_feed.parquet")
```

### Rebuild from Scratch

```python
from pathlib import Path
from vulnflow.helpers import CacheBuilder
Path("data/complete_library.parquet").unlink(missing_ok=True)  # only the cache, not the whole data/ folder
ds = CacheBuilder(include_modified=True, quiet=True).build(timeout=300.0)
ds.to_parquet("data/complete_library.parquet")
```

### Build Without CVSS Flattening

```python
from vulnflow.helpers import CacheBuilder
ds = CacheBuilder(quiet=True).build(cvss=False)
ds.to_parquet("data/nvd_raw.parquet")
```

**Partial builds:** If some feeds fail, `build()` returns data from successful
feeds and logs warnings. Re-running `build()` will re-download failed feeds.

---

## VulnDataset Operations

### Load from Different Sources

```python
from vulnflow.dataset import VulnDataset

# From Parquet
ds = VulnDataset.from_parquet("data/complete_library.parquet")

# From multiple Parquet files (upserts on cve_id)
ds = VulnDataset.from_parquet(["data/2023.parquet", "data/2024.parquet"])

# From NVD JSON
ds = VulnDataset.from_nvd("data/nvdcve-2.0-2024.json")

# From JSON export
ds = VulnDataset.from_json("data/export.json")

# From pandas DataFrame
ds = VulnDataset.from_pandas(df)

# From polars DataFrame
ds = VulnDataset.from_polars(df)
```

### Merge Datasets

```python
from vulnflow.dataset import VulnDataset
ds1 = VulnDataset.from_nvd("2024.json")
ds2 = VulnDataset.from_parquet("cache.parquet")
merged = VulnDataset.merge([ds1, ds2])
```

### Transform with Defaults

```python
ds = VulnDataset.from_parquet("data/complete_library.parquet")
ds.transform(quiet=True)  # All default transforms: flatten + KEV + EPSS + CWE enrichers
```

### Transform with Custom List

```python
from vulnflow.transforms.enrichers import KEVEnricher, EPSSEnricher
from vulnflow.transforms.flatten import CVSSFlattenTransform

ds.transform(transforms=[CVSSFlattenTransform(), KEVEnricher(), EPSSEnricher()], quiet=True)
```

### Inspect Dataset

```python
print(len(ds))           # Record count
print(ds.columns)        # All column names
print(ds.provenance)     # Extractors, transforms, timestamps
print(ds.get_status_distribution())  # {'analyzed': N, 'modified': N, ...}
```

---

## Export & Filtering

### Export to Parquet (Lossless Archive)

```python
ds.to_parquet("data/complete_library.parquet")
```

### Export to JSON (Lossless Archive)

```python
ds.to_json("data/complete_library.json")
```

### Export to Pandas (Default Status Filter)

```python
# Default: analyzed + modified only (awaiting/rejected/deferred excluded)
df = ds.to_pandas()
```

### Export to Pandas (All Statuses)

```python
df = ds.to_pandas(analyzed=True, modified=True, awaiting=True, deferred=True, rejected=True)
```

### Export to Pandas (Include Nested JSON Columns)

```python
# Includes cvss_scores, cwes, cpes, references, exploits as JSON strings
df = ds.to_pandas(include_nested=True)
```

### Export to Polars

```python
df = ds.to_polars()
df = ds.to_polars(awaiting=True, deferred=True)  # Include more statuses
```

### Filter by Severity and Export CSV

```python
df = ds.to_pandas()
critical = df[df["cvss_base_severity"] == "CRITICAL"]
critical.to_csv("data/critical_cves.csv", index=False)
print(f"Exported {len(critical)} critical CVEs")
```

### Filter by Vendor and Export

```python
df = ds.to_pandas()
apache = df[df["cpe_vendor"] == "apache"]
apache.to_parquet("data/apache_vulns.parquet")
```

### Filter by Year and Export

```python
df = ds.to_pandas()
df["year"] = df["nvd_published_at"].dt.year
df_2024 = df[df["year"] == 2024]
df_2024.to_csv("data/cves_2024.csv", index=False)
```

### Filter KEV-Listed Only

```python
df = ds.to_pandas()
kev = df[df["is_kev"] == True]
kev.to_csv("data/kev_vulns.csv", index=False)
```

---

## Pipeline Recipes

### Simple ETL Pipeline

```python
from vulnflow.pipeline import VulnPipeline
from vulnflow.extractors.nvd import NVDExtractor
from vulnflow.transforms.enrichers import KEVEnricher, EPSSEnricher
from vulnflow.loaders.files import ParquetLoader

pipeline = VulnPipeline(
    extractors=[NVDExtractor("data/nvdcve-2.0-2024.json")],
    transformers=[KEVEnricher(), EPSSEnricher()],
    loaders=[ParquetLoader("data/enriched.parquet")]
)
result = pipeline.run(quiet=True)
print(f"Processed {len(result.dataset)} records, errors: {len(result.errors)}")
```

### Multi-Source Extraction Pipeline

```python
from vulnflow.pipeline import VulnPipeline
from vulnflow.extractors.nvd import NVDExtractor
from vulnflow.extractors.files import ParquetExtractor
from vulnflow.loaders.files import ParquetLoader

pipeline = VulnPipeline(
    extractors=[
        NVDExtractor("data/nvdcve-2.0-2024.json"),
        NVDExtractor("data/nvdcve-2.0-2025.json"),
        ParquetExtractor("data/historical.parquet"),
    ],
    loaders=[ParquetLoader("data/combined.parquet")]
)
result = pipeline.run(quiet=True)
```

### Pipeline Composition with merge()

```python
from vulnflow.pipeline import VulnPipeline
from vulnflow.extractors.nvd import NVDExtractor
from vulnflow.transforms.enrichers import KEVEnricher, EPSSEnricher
from vulnflow.loaders.files import ParquetLoader, JSONLoader

extract = VulnPipeline(extractors=[NVDExtractor("data/2024.json")])
enrich = VulnPipeline(transformers=[KEVEnricher(), EPSSEnricher()])
save = VulnPipeline(loaders=[ParquetLoader("data/out.parquet"), JSONLoader("data/out.json")])

full = extract.merge(enrich).merge(save)
result = full.run(quiet=True)
```

### Pipeline with Strict Error Handling

```python
result = pipeline.run(strict=True, quiet=True)
# strict=True: fails fast on first transformer error
# strict=False (default): collects errors, continues processing
if result.errors:
    for err in result.errors:
        print(f"Error: {err}")
```

### Pipeline on Existing Dataset

```python
from vulnflow.dataset import VulnDataset
from vulnflow.pipeline import VulnPipeline
from vulnflow.transforms.enrichers import KEVEnricher, EPSSEnricher
from vulnflow.loaders.files import ParquetLoader
ds = VulnDataset.from_parquet("data/complete_library.parquet")

enrich_pipeline = VulnPipeline(
    transformers=[KEVEnricher(), EPSSEnricher()],
    loaders=[ParquetLoader("data/enriched.parquet")]
)
result = enrich_pipeline.run(dataset=ds, quiet=True)
```

### Config-Driven Pipeline

```python
from vulnflow.pipeline import VulnPipeline

pipeline = VulnPipeline.from_config({
    "extractors": [{"type": "nvd_json", "path": "data/2024.json"}],
    "transformers": ["KEVEnricher", "EPSSEnricher"],
    "loaders": [{"type": "parquet", "path": "data/output.parquet"}]
})
result = pipeline.run(quiet=True)
```

---

## CVD Analysis (Advanced)

### Infer CVD Timestamps + Compute State

```python
from vulnflow.dataset import VulnDataset
from vulnflow.transforms.inferences import EventInference
from vulnflow.transforms.computed import CVDStateTransform

ds = VulnDataset.from_parquet("data/complete_library.parquet")
ds.transform(quiet=True)  # Default enrichers first
ds.transform(transforms=[EventInference(), CVDStateTransform()], quiet=True)
df = ds.to_pandas()
```

### Conservative vs Aggressive Inference

```python
from vulnflow.transforms.inferences import EventInference

# Conservative: only authoritative sources (NVD dates, KEV)
conservative = EventInference(confidence_threshold=0.95)

# Balanced (default): includes URL date extraction
balanced = EventInference(confidence_threshold=0.7)

# Aggressive: includes age-based assumptions
aggressive = EventInference(confidence_threshold=0.1)

ds.transform(transforms=[aggressive, CVDStateTransform()], quiet=True)
```

### Find Zero-Day Exploits

```python
ds.transform(transforms=[EventInference(), CVDStateTransform()], quiet=True)
df = ds.to_pandas()
zero_days = df[df["is_zero_day_exploit"] == True]
print(f"{len(zero_days)} zero-day exploits found")
```

### Threat Classification Tags

```python
from vulnflow.transforms.inferences import TagInference

ds.transform(transforms=[TagInference()], quiet=True)
df = ds.to_pandas(include_nested=True)
# inferred_tags column contains: ["sqli", "web"], ["rce", "memory"], etc.
```

---

## Method Chaining

```python
from vulnflow.dataset import VulnDataset
df = (
    VulnDataset.from_parquet("data/complete_library.parquet")
    .transform(quiet=True)
    .to_pandas()
)
```
