# Vulnerability Management Domain Knowledge

Reference for interpreting vulnerability data and answering like a vulnerability analyst.

## Table of Contents

- [Scoring Systems](#scoring-systems)
- [Data Sources](#data-sources)
- [Zero-Day Taxonomy](#zero-day-taxonomy)
- [CVD Model](#cvd-model)
- [Prioritization Frameworks](#prioritization-frameworks)
- [Analyst Reasoning Patterns](#analyst-reasoning-patterns)

---

## Scoring Systems

### CVSS (Common Vulnerability Scoring System)

Technical severity score (0-10). Measures inherent characteristics, NOT risk.

| Severity | Score Range | Meaning |
|----------|-----------|---------|
| CRITICAL | 9.0-10.0 | Trivially exploitable, full impact |
| HIGH | 7.0-8.9 | Easily exploitable or high impact |
| MEDIUM | 4.0-6.9 | Moderate difficulty or partial impact |
| LOW | 0.1-3.9 | Hard to exploit or minimal impact |
| NONE | 0.0 | Informational |

Key vectors in vulnflow are stored as full names: `cvss_attack_vector` (`NETWORK`/`ADJACENT_NETWORK` or `ADJACENT`/`LOCAL`/`PHYSICAL`), `cvss_attack_complexity` (`LOW`/`HIGH`, plus `MEDIUM` in CVSS v2), `cvss_privileges_required` (`NONE`/`LOW`/`HIGH`), `cvss_user_interaction` (`NONE`/`REQUIRED`, plus `PASSIVE`/`ACTIVE` in CVSS v4). The last two are empty for CVSS v2 records.

**Critical nuance:** CVSS measures *technical severity*, not *risk*. A CVSS 10.0 in unused software is less urgent than a CVSS 7.0 being actively exploited. Always combine CVSS with EPSS and KEV for prioritization.

CVSS sources vary. NVD's "Primary" scores are authoritative (`is_authoritative=True`). Vendor scores (Red Hat, Microsoft) may differ due to different environmental assumptions.

### EPSS (Exploit Prediction Scoring System)

Probability of exploitation in the next 30 days (0.0-1.0). Model by FIRST.org.

Suggested thresholds (a common rule of thumb, not part of the EPSS standard):

| Percentile | Meaning | Action |
|-----------|---------|--------|
| >95th | Top 5% most likely to be exploited | Immediate remediation |
| 90-95th | High exploitation likelihood | Prioritize this sprint |
| 50-90th | Moderate likelihood | Schedule remediation |
| <50th | Low likelihood | Standard patching cycle |

**Interpreting EPSS:** EPSS=0.95 means 95% probability of exploitation activity in the next 30 days. EPSS updates daily. Historical EPSS in vulnflow tracks trend (rising EPSS = growing attacker interest).

FIRST's published evaluations show EPSS predicts exploitation better than CVSS alone, so prefer it over CVSS for likelihood.

### SSVC (Stakeholder-Specific Vulnerability Categorization)

CISA's decision framework. Not a score but a decision tree leading to:
- **Act**: Attend to immediately
- **Attend**: Attend to with elevated priority
- **Track***: Track closely, act if situation changes
- **Track**: Remediate in standard update cycle

SSVC considers: exploitation status, technical impact, automatable?, mission prevalence, public well-being. vulnflow's CVD state and EPSS data can inform SSVC decisions.

---

## Data Sources

### NVD (National Vulnerability Database)

NIST's comprehensive CVE catalog. Primary source for vulnflow.

Record statuses:
- **Analyzed**: NVD has reviewed and enriched the CVE with CVSS, CPE, CWE
- **Modified**: Previously analyzed, updated since last review
- **Awaiting Analysis**: Received but not yet reviewed by NVD analysts
- **Rejected**: Determined not to be a valid vulnerability
- **Deferred**: NVD will not analyze (delegated to CNA)

**Important:** "Awaiting" CVEs lack CVSS scores and CPE mappings. Check the `awaiting` count with `status_distribution()`: a large count means many recent CVEs have incomplete data. In vulnflow `nvd_status` values are lowercase (`analyzed`, `modified`, `awaiting`, `deferred`, `rejected`).

### KEV (Known Exploited Vulnerabilities)

CISA's catalog of vulnerabilities with confirmed active exploitation. Mandatory remediation for US federal agencies (BOD 22-01).

Key fields in vulnflow: `is_kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware` (flattened from the nested `kev` column).

**If a CVE is in KEV, it is being actively exploited.** KEV is the highest-confidence exploitation signal. EPSS predicts; KEV confirms.

### CPE (Common Platform Enumeration)

Structured product identification: `cpe:2.3:a:vendor:product:version:...`

In vulnflow: `cpe_vendor`, `cpe_product`, `cpe_version`, `cpe_fix_version`. The `cpe_fix_version` (from NVD's `versionEndExcluding`) tells you which version fixes the vulnerability.

### CWE (Common Weakness Enumeration)

Vulnerability type taxonomy. Key CWEs to know:

| CWE | Name | Significance |
|-----|------|-------------|
| CWE-79 | Cross-Site Scripting (XSS) | Most common web vuln |
| CWE-89 | SQL Injection | Data breach risk |
| CWE-787 | Out-of-Bounds Write | Memory corruption, RCE risk |
| CWE-20 | Improper Input Validation | Root cause category |
| CWE-78 | OS Command Injection | Direct system compromise |
| CWE-416 | Use After Free | Memory corruption, RCE risk |
| CWE-22 | Path Traversal | File access, often chained |
| CWE-352 | CSRF | State-changing attack |
| CWE-502 | Deserialization | Often leads to RCE |
| CWE-918 | SSRF | Cloud/internal network access |

---

## Zero-Day Taxonomy

These terms are precise in vulnerability management:

- **Zero-day vulnerability**: Vulnerability unknown to the vendor (V has not occurred in CVD terms). No patch exists.
- **Zero-day exploit**: Exploit exists before vendor awareness (X before V). The `is_zero_day_exploit` field in vulnflow.
- **Zero-day attack**: Active exploitation before vendor awareness (A before V). The `is_zero_day_attack` field in vulnflow.
- **N-day vulnerability**: Known vulnerability with patch available but not yet deployed everywhere. Most exploitation happens here.
- **Forever-day**: Known vulnerability that will never be patched (EOL product, vendor won't fix).

**Key insight:** Most exploitation targets N-day vulnerabilities, not zero-days. Patch lag is the primary risk.

---

## CVD Model

vulnflow implements the CVD (Coordinated Vulnerability Disclosure) model from the CERT/CC. Six events define the lifecycle:

| Event | Column | Meaning |
|-------|--------|---------|
| V | `v_timestamp` | Vendor becomes aware |
| F | `f_timestamp` | Fix is ready |
| D | `d_timestamp` | Fix is deployed |
| P | `p_timestamp` | Public becomes aware |
| X | `x_timestamp` | Exploit code is public |
| A | `a_timestamp` | Attacks are observed |

The `cvd_state` column encodes which events have occurred as a 6-char string (e.g., "VFdPxa" = vendor aware, fix ready, not deployed, public aware, no exploit, no attacks).

### Desiderata

12 preferred orderings that define "good" outcomes. The most important:
- **F before P**: Fix ready before public disclosure (coordination success)
- **D before A**: Fix deployed before attacks (remediation success)
- **V before X**: Vendor aware before exploit published (early warning success)

The `desiderata_count` column (0-12) measures how many orderings were achieved. Higher = better-managed vulnerability.

### Derived Fields

- `fix_lag_days`: Days between fix ready (F) and fix deployed (D)
- `exploit_lag_days`: Days between public awareness (P) and exploit public (X)
- `is_uncoordinated`: Disclosure happened without vendor awareness (P before V)
- `is_premature_disclosure`: Public disclosure before fix ready (P before F)
- `threat_state`: Categorical threat level derived from CVD state

---

## Prioritization Frameworks

### Combining Signals

A vulnerability analyst combines multiple signals. Priority order:

1. **KEV + CRITICAL CVSS**: Active exploitation of critical vulnerability. Drop everything.
2. **KEV + any CVSS**: Active exploitation confirmed. Remediate by KEV due date.
3. **High EPSS (>0.9) + HIGH/CRITICAL**: Very likely to be exploited soon. Prioritize.
4. **High EPSS + any CVSS**: Likely exploitation regardless of severity label.
5. **CRITICAL CVSS + low EPSS**: Severe but unlikely to be exploited. Schedule.
6. **CWE patterns**: Clusters of same CWE type suggest systematic weakness.

### Risk vs Severity

- **Severity** (CVSS): How bad could it be?
- **Likelihood** (EPSS): How likely is exploitation?
- **Risk** = Severity x Likelihood x Exposure
- **Urgency** (KEV): Is it being exploited NOW?

### Remediation Velocity Metrics

Useful metrics a vulnerability analyst tracks:
- Mean time to remediate (MTTR) by severity
- Patch lag distribution (D - F across CVEs)
- Exposure window (time between P and D)
- Vulnerability debt (count of unpatched CVEs over time)

---

## Analyst Reasoning Patterns

When answering questions, think like a vulnerability analyst:

### "What should I worry about?"
Combine KEV status, EPSS score, CVSS severity. Look for the intersection of high-impact AND high-likelihood. A CVSS 10.0 with EPSS 0.01 is less urgent than a CVSS 7.5 with EPSS 0.95.

### "What are the trends?"
Year-over-year CVE volume shows discovery rate, not risk. Rising critical percentage matters more than rising total count. Look at CWE distribution shifts (are we seeing more memory corruption? more web vulns?).

### "How well are we coordinating?"
Use CVD desiderata. High `desiderata_count` means good coordination. Look at `is_uncoordinated` and `is_premature_disclosure` rates. Compare `fix_lag_days` distributions.

### "What's the exposure window?"
Time between public disclosure (P) and fix deployment (D) is the risk window. During this time, attackers can develop exploits. Shorter = better. Compute it from `p_timestamp` and `d_timestamp`. For how fast attacks follow disclosure, look at `public_to_attack_days` (P to A).

### "Which vendors have the most critical vulnerabilities?"
Use `cpe_vendor` + severity distribution. But also check fix velocity: which vendors ship fixes fastest (F - V days)?

### Caveats to always mention
- NVD backlog means recent CVEs may lack CVSS scores ("Awaiting Analysis")
- CVSS is severity, not risk. Always pair with EPSS/KEV for risk.
- Year-over-year increases partly reflect better discovery, not more insecure software
- CPE data can be incomplete, especially for open-source software
- Partial year data should not be annualized without caveat
