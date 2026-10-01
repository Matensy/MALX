import hashlib
import io
import sqlite3
import tarfile

import py7zr
import pytest

from backend.analyzers import hashing
from backend.analyzers.identify import identify
from tests.samples import factory


def ident_bytes(tmp_path, name, data):
    p = tmp_path / "x.bin"
    p.write_bytes(data)
    return identify(p, name)


@pytest.mark.parametrize("name,builder,expected,category", [
    ("a.exe", factory.benign_pe, "pe", "pe"),
    ("a.so", factory.build_elf, "elf", "elf"),
    ("a.zip", lambda: factory.zip_bytes({"a.txt": b"x"}), "zip", "archive"),
    ("a.pdf", factory.minimal_pdf, "pdf", "pdf"),
    ("a.docx", factory.ooxml_template_injection, "ooxml", "office"),
    ("a.rtf", factory.rtf_exploit_like, "rtf", "document"),
    ("a.lnk", factory.lnk_powershell, "lnk", "lnk"),
    ("a.apk", factory.banker_like_apk, "apk", "apk"),
    ("a.png", factory.tiny_png, "png", "image"),
    ("a.ps1", factory.encoded_powershell, "script", "script"),
    ("a.tar.gz", factory.tar_gz_sample, "gzip", "archive"),
    ("a.tar", factory.path_traversal_tar, "tar", "archive"),
])
def test_identify_types(tmp_path, name, builder, expected, category):
    ident = ident_bytes(tmp_path, name, builder())
    assert ident.detected_type == expected
    assert ident.category == category
    assert ident.confidence >= 0.6
    assert ident.magic_hex


def test_identify_pe_details(tmp_path):
    ident = ident_bytes(tmp_path, "x.exe", factory.benign_pe())
    assert ident.label.startswith("PE32+ executable")
    assert ident.architecture == "x86-64"
    dll = ident_bytes(tmp_path, "x.dll", factory.build_pe(dll=True))
    assert "DLL" in dll.label


def test_identify_dex_sqlite_7z(tmp_path):
    assert ident_bytes(tmp_path, "c.dex", factory.build_dex(["abc"])).detected_type == "dex"
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.execute("create table t(x)")
    con.commit()
    con.close()
    assert identify(db, "t.db").detected_type == "sqlite"
    sz = tmp_path / "a.7z"
    with py7zr.SevenZipFile(sz, "w") as z:
        z.writestr(b"hello", "h.txt")
    assert identify(sz, "a.7z").detected_type == "7z"


def test_extension_mismatch(tmp_path):
    ident = ident_bytes(tmp_path, "invoice.pdf", factory.benign_pe())
    assert ident.detected_type == "pe"
    assert ident.extension_mismatch
    assert ".pdf" in ident.mismatch_reason
    ok = ident_bytes(tmp_path, "setup.exe", factory.benign_pe())
    assert not ok.extension_mismatch


def test_double_extension_flag(tmp_path):
    ident = ident_bytes(tmp_path, "report.pdf.exe", factory.benign_pe())
    assert ident.details.get("double_extension")


def test_text_with_binary_extension_is_mismatch(tmp_path):
    ident = ident_bytes(tmp_path, "photo.jpg", factory.encoded_powershell())
    assert ident.category == "script"
    assert ident.extension_mismatch


def test_unknown_and_empty(tmp_path):
    assert ident_bytes(tmp_path, "x", b"").detected_type == "empty"
    import os
    assert ident_bytes(tmp_path, "x", os.urandom(4096)).detected_type == "unknown"


def test_hashes_match_hashlib(tmp_path):
    data = factory.benign_pe()
    p = tmp_path / "x.bin"
    p.write_bytes(data)
    h, lims = hashing.compute_hashes(p, len(data), 64 * 1024 * 1024)
    assert h["md5"] == hashlib.md5(data).hexdigest()
    assert h["sha1"] == hashlib.sha1(data).hexdigest()
    assert h["sha256"] == hashlib.sha256(data).hexdigest()
    assert h["sha512"] == hashlib.sha512(data).hexdigest()
    assert h["ssdeep"] and ":" in h["ssdeep"]
    assert h["tlsh"] and h["tlsh"].startswith("T1") and len(h["tlsh"]) == 72


def test_tlsh_reference_vector():
    # Expected value produced by the reference TLSH implementation (py-tlsh 4.x/5.x).
    data = bytes(range(256)) * 4 + b"MALX evidence-first static analysis " * 20
    assert hashing.tlsh_py(data) == "T1B631CC50612964EF8F1F4DC9F89E03BACB896BAF13D9001279644E829D429E3850D8BA"
    import random
    r = random.Random(1337)
    d2 = bytes(r.getrandbits(8) for _ in range(5000))
    assert hashing.tlsh_py(d2) == "T196A18FD3BC5786EA01311EF3822EBE16B8F40A460253F1247575546ABF81B8640713CE"
    assert hashing.tlsh_py(b"a" * 40) is None          # too short
    assert hashing.tlsh_py(b"\x00" * 4096) is None     # no variance


def test_fuzzy_hash_limit(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"x" * 2048)
    h, lims = hashing.compute_hashes(p, 2048, 1024)
    assert h["ssdeep"] is None and h["tlsh"] is None
    assert any("Fuzzy hashes skipped" in l for l in lims)
