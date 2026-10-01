# MALX test lab

Synthetic, **harmless** samples for tests and demos. They are generated at test time by
[`factory.py`](factory.py) — no malware is stored in this repository.

| Sample | Purpose |
|---|---|
| `benign_pe` | Minimal valid PE32+ that only returns — must stay *BENIGN_INDICATORS* |
| `packed_like_sample` | UPX-like section names, RWX sections, high entropy, few imports |
| `suspicious_strings_sample` | Browser credential paths, DPAPI import, webhook URL, VM/tool names |
| `injector_sample` | VirtualAllocEx/WriteProcessMemory/CreateRemoteThread import chain |
| `fake_persistence_sample` | Run key, scheduled task and PowerShell cradle as inert text |
| `encoded_powershell` | `-EncodedCommand` payload decoded statically |
| `linux_backdoor_like` | ELF with RWX segment, exec stack, `/tmp` RUNPATH, reverse-shell text |
| `archive_nested_sample` | ZIP → PDF/EXE/PNG + nested ZIP → DLL (recursive extraction) |
| `path_traversal_test_archive` | `../../../../etc/passwd`, absolute paths, symlinks, device files |
| `zip_bomb_test_metadata` | ~1000:1 compression ratio member (zeros) |
| `deep_nested`, `many_files`, `huge_filename`, `corrupted` | Limit and robustness tests |
| `pdf_with_javascript`, `template_injection.docx`, `equation_object.rtf`, `powershell_shortcut.lnk` | Document threats |
| `banker_like.apk` | Binary-XML manifest with SMS/accessibility permissions + DEX strings |
| `vulnerable_project.zip` | Flask/Express project with SQLi, command injection, SSRF, secrets |
| `invoice.pdf` | A PE named `.pdf` (extension mismatch) |

Write them to disk for manual exploration:

```bash
python scripts/generate_samples.py   # -> tests/samples/generated/ (git-ignored)
```

The EICAR test string is assembled at runtime from fragments so the repository itself is
not flagged by anti-virus products.
