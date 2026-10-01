from backend.analyzers.base import ExtractedString
from backend.analyzers.ioc import IOCEnricher, extract_iocs
from backend.analyzers.strings_engine import StringClassifier, extract_strings
from backend.core.enums import StringClass


def S(*values):
    return [ExtractedString(i, "ascii", v) for i, v in enumerate(values)]


def iocs(*values):
    return {(r.type, r.normalized) for r in extract_iocs(S(*values))}


def test_extract_ascii_and_utf16(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00\x01ASCII string here\x00\x00" + "Wide string text".encode("utf-16-le") + b"\x00\x00\xff" + "olá mundo çã".encode())
    found, truncated = extract_strings(p, p.stat().st_size, 1 << 20)
    values = {(s.encoding, s.value) for s in found}
    assert ("ascii", "ASCII string here") in values
    assert ("utf-16le", "Wide string text") in values
    assert any(e == "utf-8" and "olá" in v for e, v in values)
    assert not truncated


def test_string_scan_truncation(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"AAAAAAAAAA\x00" * 1000)
    found, truncated = extract_strings(p, p.stat().st_size, 100)
    assert truncated and all(s.offset < 100 for s in found)


def test_classification(pack):
    strings = S("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "hello world", "VirtualAllocEx", "kernel32.dll",
                "vssadmin delete shadows /all /quiet")
    StringClassifier(pack).classify(strings, imports=set())
    by = {s.value: s for s in strings}
    assert by["hello world"].classification == StringClass.NORMAL
    assert by["Software\\Microsoft\\Windows\\CurrentVersion\\Run"].classification == StringClass.SUSPICIOUS
    assert by["vssadmin delete shadows /all /quiet"].classification == StringClass.HIGH_RISK
    assert "api_name_unimported" in by["VirtualAllocEx"].tags
    assert "dll_name" in by["kernel32.dll"].tags
    assert by["powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"].classification == StringClass.HIGH_RISK


def test_ioc_extraction_basic():
    got = iocs("connect to http://evil.example-c2.top:8443/gate.php?id=1",
               "fallback 203.0.113.7 and 2001:db8::1234:5678", "mail admin@malicious-domain.ru now",
               "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "C:\\Users\\Public\\payload.exe",
               "/etc/ld.so.preload", "Global\\MyMutexName123")
    assert ("url", "http://evil.example-c2.top:8443/gate.php?id=1") in got
    assert ("domain", "evil.example-c2.top") in got
    assert ("ipv4", "203.0.113.7") in got
    assert ("ipv6", "2001:db8::1234:5678") in got
    assert ("email", "admin@malicious-domain.ru") in got
    assert ("registry", "hklm\\software\\microsoft\\windows\\currentversion\\run") in got
    assert ("file_path", "c:\\users\\public\\payload.exe") in got
    assert ("file_path", "/etc/ld.so.preload") in got
    assert ("mutex", "Global\\MyMutexName123") in got


def test_ioc_false_positive_controls():
    got = iocs("setup.py", "System.Net.Http", "java.lang.reflect", "com.google.android.gms", "Version 1.0.0.0",
               "this.store = x", "user.email", "C:\\temp\\run.sh")
    domains = {v for t, v in got if t == "domain"}
    assert domains == set()
    assert not any(t == "ipv4" for t, _ in got)


def test_crypto_wallet_validation():
    got = iocs("pay to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT please", "not a wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyX")
    wallets = {v for t, v in got if t == "crypto_wallet"}
    assert wallets == {"1BoatSLRHtKNngkdXEeobR76b53LETtpyT"}


def test_onion_and_enrichment(pack):
    raws = extract_iocs(S("http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion/x",
                          "http://victim-panel.duckdns.org/a", "https://www.microsoft.com/en-us", "http://10.0.0.5:4444/"))
    enr = IOCEnricher(pack)
    info = {(r.type, r.normalized): enr.enrich(r) for r in raws}
    assert info[("domain", "victim-panel.duckdns.org")]["service"] == "dynamic_dns"
    assert info[("domain", "www.microsoft.com")].get("common") is True
    assert info[("url", "http://10.0.0.5:4444/")]["unusual_port"] == 4444
    assert info[("ipv4", "10.0.0.5")].get("private") is True
    assert any(t == "onion" for t, _ in info)
