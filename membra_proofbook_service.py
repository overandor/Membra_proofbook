"""MEMBRA ProofBook operational service.

Canonical proof/audit service for MEMBRA federation. This is a dependency-light
FastAPI service that stores reproducible proof hashes, subject timelines, and
verification checks.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

APP_NAME = "MEMBRA ProofBook"
APP_VERSION = "1.0.0-neomorphic"
DB_PATH = Path(os.getenv("APP_DB_PATH", "/tmp/membra_proofbook.sqlite3"))
app = FastAPI(title=APP_NAME, version=APP_VERSION)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:14]}"


def canonical_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS proof_records(
          proof_id TEXT PRIMARY KEY,
          source_system TEXT NOT NULL,
          subject_type TEXT NOT NULL,
          subject_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          proof_hash TEXT NOT NULL,
          parent_hash TEXT,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_proof_subject ON proof_records(subject_type, subject_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_proof_hash ON proof_records(proof_hash);
        """)


class ProofIn(BaseModel):
    source_system: str = "membra"
    subject_type: str
    subject_id: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    parent_hash: str | None = None
    status: str = "recorded"


class VerifyIn(BaseModel):
    payload: dict[str, Any]
    expected_hash: str


init_db()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION, "db": str(DB_PATH)}


@app.post("/api/proofs")
def create_proof(data: ProofIn) -> dict[str, Any]:
    envelope = {
        "source_system": data.source_system,
        "subject_type": data.subject_type,
        "subject_id": data.subject_id,
        "event_type": data.event_type,
        "payload": data.payload,
        "parent_hash": data.parent_hash,
        "status": data.status,
    }
    proof_hash = canonical_hash(envelope)
    row = {
        "proof_id": new_id("proof"),
        "source_system": data.source_system,
        "subject_type": data.subject_type,
        "subject_id": data.subject_id,
        "event_type": data.event_type,
        "payload_json": json.dumps(data.payload, sort_keys=True, default=str),
        "proof_hash": proof_hash,
        "parent_hash": data.parent_hash,
        "status": data.status,
        "created_at": now(),
    }
    with db() as conn:
        conn.execute("INSERT INTO proof_records VALUES(?,?,?,?,?,?,?,?,?,?)", tuple(row.values()))
    return {**row, "payload": data.payload}


@app.get("/api/proofs/{proof_id}")
def get_proof(proof_id: str) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM proof_records WHERE proof_id=?", (proof_id,)).fetchone()
    if not row:
        raise HTTPException(404, "proof not found")
    out = dict(row)
    out["payload"] = json.loads(out.pop("payload_json"))
    return out


@app.get("/api/subjects/{subject_type}/{subject_id}/timeline")
def subject_timeline(subject_type: str, subject_id: str) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM proof_records WHERE subject_type=? AND subject_id=? ORDER BY created_at ASC",
            (subject_type, subject_id),
        ).fetchall()
    return {"count": len(rows), "records": [dict(r) for r in rows]}


@app.post("/api/verify")
def verify(data: VerifyIn) -> dict[str, Any]:
    actual = canonical_hash(data.payload)
    return {"valid": actual == data.expected_hash, "actual_hash": actual, "expected_hash": data.expected_hash}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
