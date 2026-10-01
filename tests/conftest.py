"""Shared fixtures. Analyses run in "inline" worker mode for speed; one test covers
the isolated process mode explicitly."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Any

import pytest

from backend.analyzers.base import AnalysisContext, ArtifactContext
from backend.core.config import Limits, Settings, reset_settings_cache

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
H = {"X-MALX-Request": "1"}


@pytest.fixture()
def storage_root(tmp_path: Path) -> Path:
    p = tmp_path / "storage"
    p.mkdir()
    return p


def make_settings(storage_root: Path, mode: str = "inline", **limits: Any) -> Settings:
    os.environ["MALX_CONFIG"] = str(ROOT / "malx.yaml")
    reset_settings_cache()
    s = Settings(storage_dir=storage_root, rules_dir=RULES, database_url=f"sqlite:///{storage_root / 'malx.db'}",
                 workers={"mode": mode, "max_concurrent_analyses": 1},
                 integrations={"local_tools_enabled": False})
    for k, v in limits.items():
        setattr(s.limits, k, v)
    return s


@pytest.fixture()
def client_factory(storage_root: Path):
    from fastapi.testclient import TestClient

    from backend.main import create_app

    clients = []

    def factory(mode: str = "inline", **limits: Any):
        app = create_app(make_settings(storage_root, mode, **limits))
        c = TestClient(app)
        c.__enter__()
        clients.append(c)
        return c

    yield factory
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture()
def client(client_factory):
    return client_factory()


def upload(client, files: list[tuple[str, bytes]], **fields) -> str:
    r = client.post("/api/analyses", headers=H, files=[("files", (n, d)) for n, d in files], data=fields)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def wait(client, aid: str, timeout: float = 120) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        a = client.get(f"/api/analyses/{aid}").json()
        if a["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            return a
        time.sleep(0.1)
    raise AssertionError(f"analysis {aid} did not finish")


def analyze(client, name: str, data: bytes, **fields) -> dict:
    aid = upload(client, [(name, data)], **fields)
    a = wait(client, aid)
    assert a["status"] == "COMPLETED", a.get("error")
    return a


@pytest.fixture()
def ctx(storage_root: Path):
    def make(limits: Limits | None = None, password: str | None = None) -> AnalysisContext:
        return AnalysisContext("b" * 32, limits or Limits(), storage_root, password=password)

    return make


def artifact_from_bytes(ctx: AnalysisContext, name: str, data: bytes) -> ArtifactContext:
    from backend.analyzers.identify import identify

    qdir = ctx.storage_root / "quarantine" / ctx.analysis_id
    qdir.mkdir(parents=True, exist_ok=True)
    iid = os.urandom(16).hex()
    path = qdir / f"{iid}.bin"
    path.write_bytes(data)
    art = ArtifactContext(id=iid, path=path, storage_rel=f"quarantine/{ctx.analysis_id}/{iid}.bin", display_name=name, size=len(data))
    art.ident = identify(path, name)
    return ctx.add_artifact(art)


@pytest.fixture(scope="session")
def pack():
    from backend.rules.loader import load_rule_pack

    return load_rule_pack(RULES)
