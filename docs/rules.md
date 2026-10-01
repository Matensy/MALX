# Writing rules

All detection content is **data** under `rules/` — loaded with `yaml.safe_load`, validated, never
executed. Adding a rule needs no code change. `pytest tests/test_rules_correlation.py` validates
every pack (unknown predicates, unknown MITRE ids, unknown string tags, dangling rule references).

```
rules/
  signatures/strings.yaml   string classification (NORMAL → INTERESTING → SUSPICIOUS → HIGH_RISK)
  signatures/apis.yaml      API catalogue with categories and legitimate uses
  signatures/network.yaml   common domains, abused services, dynamic DNS, suspicious TLDs, ports
  signatures/packers.yaml   packer / protector / installer / compiler fingerprints
  heuristics/*.yaml         heuristic rules → evidence
  correlation/*.yaml        correlation rules → findings
  mitre/techniques.yaml     offline ATT&CK subset used for names/tactics
  yara/*.yar                YARA rules (meta: description, author, reference, severity, category, mitre)
  appsec/*.yaml             code-weakness and secret patterns
  advisories/               local OSV advisory database (empty by default)
```

## Heuristic rules

```yaml
- id: HEUR-CRED-001
  name: Browser credential database access
  category: credential_access        # evidence category / risk dimension
  severity: high                     # info | low | medium | high | critical
  confidence: 0.7
  reliability: high                  # low | medium | high
  applies_to: [pe, elf]              # optional: detected types / categories / languages
  conditions:
    all:
      - string_tags_any: [browser_credentials]
      - any:
          - imports_any: [CryptUnprotectData]
          - strings_any: ["encrypted_key", "password_value"]
  explanation: "What the match means."
  legitimate: "When legitimate software does the same."
  mitre: [T1555.003]
```

Combinators: `all`, `any`, `not`, `at_least: {n: 2, of: [...]}`.

| Predicate | Example |
|---|---|
| `file_type` | `[pe, script, executable, document, archive, powershell]` |
| `imports_any` / `imports_all` | API names (A/W suffix tolerant) |
| `imports_count_gte` / `imports_count_lte` | `5` |
| `exports_any` | `[ReflectiveLoader]` |
| `strings_any` / `strings_all` | case-insensitive substrings over all strings (file, decoded, VBA, DEX, FLOSS…) |
| `strings_count` | `{any: [...], min: 3}` |
| `strings_regex` | Python regex (case-insensitive) |
| `string_tags_any` / `string_tags_count` | tags from `signatures/strings.yaml` (+ `api_name_unimported`, `dll_name`) |
| `ioc_any` / `ioc_count` | `[url, ipv4, onion, crypto_wallet]` / `{type: url, min: 2}` (non-common IOCs) |
| `ioc_flag_any` | `[ip_host, unusual_port, suspicious_tld]` |
| `ioc_service_any` | `[dynamic_dns, tunnels, paste_sites, file_sharing, chat_api, ip_lookup, logger]` |
| `evidence_any` | evidence types already produced for the artifact |
| `evidence_category_count` | `{category: anti_analysis, min: 2}` |
| `tags_any` / `tags_all` | artifact tags (`packed`, `dotnet`, `perm:READ_SMS`, `static`, …) |
| `entropy_gte`, `size_gte`, `size_lte` | numbers |
| `extension_mismatch`, `extension_in`, `double_extension` | identification results |
| `name_regex`, `name_issues_any` | display name / `bidi_override`, `null_byte`… |
| `in_archive`, `child_type_any` | container relationships |
| `metadata` | `{path: "pe.import_count", lte: 5}` |

Rules run twice, so a rule may build on evidence produced by another rule.

## Correlation rules

```yaml
- id: CORR-CRED-001
  title: Potential credential theft with an exfiltration channel
  hypothesis: credential_stealer
  category: credential_access
  severity: high
  min_sources: 2                         # distinct engines required
  scope: unit                            # unit (default) | artifact
  requires:                              # every group must match
    - {categories: [credential_access], min_severity: medium}
    - {categories: [network]}
  supporting:                            # optional, raise confidence
    - {categories: [anti_analysis, defense_evasion, packing]}
    - {types: [reverse_api_sequence], categories: [credential_access]}
    - {rules: [HEUR-NET-004, "yara:malx_core:MALX_Chat_Webhook_Exfiltration_Channel"], min_count: 1}
  what: "…"  why: "…"  recommendation: "…"
```

## YARA

Put `.yar` files in `rules/yara/`. Required meta: `description`, `author`, `reference`,
`severity`; optional `category`, `mitre` (comma separated), `confidence`, `reliability`.
Broken files are reported in Settings and skipped; the rest still load.

## AppSec patterns

```yaml
- {id: CODE-SQL-001, kind: code, title: "...", languages: [python], severity: high, cwe: CWE-89,
   category: sql_injection, pattern: '…regex…', exclude: '…optional regex…', ignore_case: true,
   description: "…", recommendation: "…"}
```

`kind: secret` patterns are masked before storage. Line-based patterns flag code for review; they
do not prove data flow.
