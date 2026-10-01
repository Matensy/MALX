# Local advisory database

MALX matches dependencies against advisories stored **here, offline**. The directory ships
empty on purpose: MALX never downloads data by itself and never invents CVEs.

Populate it with [OSV](https://osv.dev) dumps you download explicitly:

```bash
# e.g. https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
python scripts/import_osv.py PyPI-all.zip npm-all.zip Maven-all.zip
```

Accepted files: `*.json` (one OSV record or a list) and `*.jsonl` (one record per line).
Matching uses OSV `ECOSYSTEM`/`SEMVER` ranges (`introduced` / `fixed` / `last_affected`) and
explicit `versions` lists. Dependencies declared with a range (e.g. `^4.17.1`) are reported
with lower confidence because the installed version may differ.
