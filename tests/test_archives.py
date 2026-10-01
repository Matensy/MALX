"""Archive validation, traversal protection, bombs, depth and count limits."""

import os

from backend.analyzers import archive
from backend.core.config import Limits
from tests.conftest import artifact_from_bytes
from tests.samples import factory


def _extracted_files(ctx):
    d = ctx.storage_root / "extracted" / ctx.analysis_id
    return sorted(p for p in d.rglob("*") if p.is_file()) if d.exists() else []


def test_nested_archive_extraction(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "sample.zip", factory.archive_nested_sample())
    children = archive.analyze_archive(c, art)
    names = sorted(ch.display_name for ch in children)
    assert names == ["document.pdf", "image.png", "invoice.exe", "payload.zip"]
    # every extracted file uses an internal UUID name inside the analysis directory
    for f in _extracted_files(c):
        assert f.suffix == ".bin" and len(f.stem) == 32
        assert not os.access(f, os.W_OK) or os.geteuid() == 0
    payload = next(ch for ch in children if ch.display_name == "payload.zip")
    from backend.analyzers.identify import identify
    payload.ident = identify(payload.path, payload.display_name)
    grand = archive.analyze_archive(c, payload)
    assert [g.display_name for g in grand] == ["loader.dll"]
    assert grand[0].depth == 2 and grand[0].path_in_archive == "loader.dll"


def test_zip_path_traversal_and_symlink(ctx, tmp_path):
    c = ctx()
    art = artifact_from_bytes(c, "evil.zip", factory.path_traversal_zip())
    children = archive.analyze_archive(c, art)
    types = {e.type for e in c.evidence}
    assert "archive_path_traversal" in types
    assert "archive_link_entries" in types
    # nothing was written outside the extraction directory
    assert not (tmp_path / "etc").exists()
    assert not os.path.exists("/abs/evil.txt")
    base = c.storage_root / "extracted" / c.analysis_id
    for ch in children:
        assert base in ch.path.resolve().parents
    # traversal members are shown with a sanitised path, never "../"
    assert all(".." not in (ch.path_in_archive or "") for ch in children)
    members = art.metadata["archive"]["members"]
    link = next(m for m in members if m["name"] == "link_to_etc")
    assert link["kind"] == "symlink" and not link["extracted"]


def test_tar_traversal_symlink_device(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "evil.tar", factory.path_traversal_tar())
    children = archive.analyze_archive(c, art)
    kinds = {m["name"]: m["kind"] for m in art.metadata["archive"]["members"]}
    assert kinds["evil_link"] == "symlink" and kinds["dev_null"] == "device"
    assert {ch.display_name for ch in children} == {"escape.txt", "readme.txt"}
    types = {e.type for e in c.evidence}
    assert {"archive_path_traversal", "archive_link_entries", "archive_special_files"} <= types


def test_zip_bomb_detection(ctx):
    c = ctx(Limits(max_compression_ratio=100))
    art = artifact_from_bytes(c, "bomb.zip", factory.zip_bomb_sample(8))
    children = archive.analyze_archive(c, art)
    assert children == []
    ev = [e for e in c.evidence if e.type == "decompression_bomb"]
    assert ev and ev[0].severity.value == "high"
    assert not _extracted_files(c), "partially written member must be removed"


def test_extracted_size_budget(ctx):
    c = ctx(Limits(max_extracted_size=3 * 1024 * 1024, max_compression_ratio=100000))
    art = artifact_from_bytes(c, "bomb.zip", factory.zip_bomb_sample(8))
    archive.analyze_archive(c, art)
    assert any(e.type == "decompression_bomb" for e in c.evidence)
    assert c.extracted_bytes <= 3 * 1024 * 1024 + 1024 * 1024


def test_too_many_files(ctx):
    c = ctx(Limits(max_files_per_archive=50))
    art = artifact_from_bytes(c, "many.zip", factory.many_files_zip(120))
    assert archive.analyze_archive(c, art) == []
    assert any(e.type == "archive_limit" for e in c.evidence)


def test_depth_limit(ctx):
    c = ctx(Limits(max_archive_depth=3))
    from backend.analyzers.identify import identify
    art = artifact_from_bytes(c, "deep.zip", factory.deep_nested_zip(6))
    queue = [art]
    while queue:
        a = queue.pop()
        a.ident = identify(a.path, a.display_name)
        queue += archive.analyze_archive(c, a)
    assert max(a.depth for a in c.artifacts) == 3
    assert any(e.type == "archive_depth_limit" for e in c.evidence)


def test_corrupted_archive(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "broken.zip", factory.corrupted_zip())
    assert archive.analyze_archive(c, art) == []
    assert any(e.type == "corrupted_archive" for e in c.evidence) or art.metadata["archive"]["stats"].get("error")


def test_huge_and_deep_member_names(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "names.zip", factory.huge_filename_zip())
    children = archive.analyze_archive(c, art)
    assert len(children) == 2
    assert all(len(ch.display_name) <= 255 for ch in children)
    assert any(e.type == "archive_malformed_names" for e in c.evidence)


def test_encrypted_zip_with_password(ctx):
    import io

    import pyzipper

    bio = io.BytesIO()
    with pyzipper.AESZipFile(bio, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"correct horse")
        z.writestr("secret.txt", b"hidden content http://198.51.100.99/x")
    data = bio.getvalue()
    c = ctx(password="correct horse")
    art = artifact_from_bytes(c, "protected.zip", data)
    children = archive.analyze_archive(c, art)
    assert [ch.display_name for ch in children] == ["secret.txt"]
    assert children[0].path.read_bytes().startswith(b"hidden content")
    c2 = ctx(password="wrong")
    art2 = artifact_from_bytes(c2, "protected.zip", data)
    assert archive.analyze_archive(c2, art2) == []
    assert any("encrypted member" in l for l in c2.limitations)


def test_gzip_single_stream(ctx):
    import gzip

    c = ctx()
    art = artifact_from_bytes(c, "notes.txt.gz", gzip.compress(b"hello world " * 100))
    children = archive.analyze_archive(c, art)
    assert children[0].display_name == "notes.txt"
    assert children[0].path.read_bytes() == b"hello world " * 100
