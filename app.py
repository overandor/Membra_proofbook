"""MEMBRA ProofBook — verifiable proof ledger and audit trail.

ProofBook records public hashes, event envelopes, evidence metadata, consent scope,
review status, and exportable audit trails. It does not store raw private memories,
private keys, seed phrases, or unconsented personal material.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import gradio as gr
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

APP_NAME = "MEMBRA ProofBook"
APP_VERSION = "1.1.0"
DB_PATH = Path(os.getenv("APP_DB_PATH", "/tmp/membra_proofbook.sqlite3"))
MEMBRA_EVENT_SECRET = os.getenv("MEMBRA_EVENT_SECRET", "")
api = FastAPI(title=APP_NAME, version=APP_VERSION)


class ProofIn(BaseModel):
    subject_type: str = Field(description="asset|campaign|wear_kit|relay_job|artifact|wallet_event")
    subject_id: str
    owner_email: str = ""
    proof_type: str = "photo_timestamp_metadata"
    evidence_url: str = ""
    consent_scope: str = "public hash, timestamp, proof metadata, and review status only"
    reviewer: str = "system"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReviewIn(BaseModel):
    status: str = "approved"
    reviewer: str = "operator"
    notes: str = ""


class MembraEventIn(BaseModel):
    event_id: str
    event_type: str
    source_module: str
    subject_type: str
    subject_id: str
    owner_id: str | None = None
    correlation_id: str | None = None
    causation_id: str | None = None
    created_at: str
    consent_scope: str | None = None
    risk_level: str = "normal"
    payload: dict[str, Any] = Field(default_factory=dict)
    proof_hash: str | None = None
    signature: str | None = None


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def verify_event_signature(event: dict[str, Any]) -> bool:
    if not MEMBRA_EVENT_SECRET:
        return True
    supplied = event.get("signature") or ""
    unsigned = dict(event)
    unsigned["signature"] = None
    expected = "hmac_sha256:" + hmac.new(MEMBRA_EVENT_SECRET.encode("utf-8"), canonical(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS proofs(
          proof_id TEXT PRIMARY KEY,
          subject_type TEXT,
          subject_id TEXT,
          owner_email TEXT,
          proof_type TEXT,
          evidence_url TEXT,
          consent_scope TEXT,
          proof_hash TEXT,
          status TEXT,
          reviewer TEXT,
          review_notes TEXT,
          metadata_json TEXT,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_events(
          event_id TEXT PRIMARY KEY,
          proof_id TEXT,
          event_type TEXT,
          actor TEXT,
          metadata_json TEXT,
          event_hash TEXT,
          created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events(
          event_id TEXT PRIMARY KEY,
          event_type TEXT,
          source_module TEXT,
          subject_type TEXT,
          subject_id TEXT,
          owner_id TEXT,
          risk_level TEXT,
          proof_hash TEXT,
          signature TEXT,
          payload_json TEXT,
          status TEXT,
          created_at TEXT,
          ingested_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_proofbook_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_proofbook_events_subject ON events(subject_type, subject_id);
        """)


init_db()


def record_audit(proof_id: str, event_type: str, actor: str, metadata: dict[str, Any]) -> dict[str, Any]:
    payload = {"proof_id": proof_id, "event_type": event_type, "actor": actor, "metadata": metadata, "created_at": now()}
    event = {"event_id": new_id("audit"), "proof_id": proof_id, "event_type": event_type, "actor": actor, "metadata_json": json.dumps(metadata, default=str), "event_hash": hash_payload(payload), "created_at": payload["created_at"]}
    with db() as conn:
        conn.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?)", tuple(event.values()))
    return event


def create_proof_record(data: ProofIn) -> dict[str, Any]:
    proof_id = new_id("proof")
    created = now()
    public_payload = {
        "subject_type": data.subject_type,
        "subject_id": data.subject_id,
        "owner_email_hash": hashlib.sha256(data.owner_email.lower().strip().encode()).hexdigest() if data.owner_email else "",
        "proof_type": data.proof_type,
        "evidence_url": data.evidence_url,
        "consent_scope": data.consent_scope,
        "metadata": data.metadata,
        "created_at": created,
    }
    row = {
        "proof_id": proof_id,
        "subject_type": data.subject_type,
        "subject_id": data.subject_id,
        "owner_email": data.owner_email,
        "proof_type": data.proof_type,
        "evidence_url": data.evidence_url,
        "consent_scope": data.consent_scope,
        "proof_hash": hash_payload(public_payload),
        "status": "submitted_pending_review",
        "reviewer": data.reviewer,
        "review_notes": "",
        "metadata_json": json.dumps(data.metadata, default=str),
        "created_at": created,
        "updated_at": created,
    }
    with db() as conn:
        conn.execute("INSERT INTO proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(row.values()))
    record_audit(proof_id, "proof_submitted", data.reviewer, public_payload)
    return row


def review_record(proof_id: str, data: ReviewIn) -> dict[str, Any]:
    allowed = {"approved", "rejected", "needs_more_evidence", "fraud_hold", "archived"}
    if data.status not in allowed:
        raise HTTPException(400, f"status must be one of {sorted(allowed)}")
    with db() as conn:
        row = conn.execute("SELECT * FROM proofs WHERE proof_id=?", (proof_id,)).fetchone()
    if not row:
        raise HTTPException(404, "proof not found")
    updated = now()
    with db() as conn:
        conn.execute("UPDATE proofs SET status=?, reviewer=?, review_notes=?, updated_at=? WHERE proof_id=?", (data.status, data.reviewer, data.notes, updated, proof_id))
    record_audit(proof_id, f"proof_reviewed:{data.status}", data.reviewer, {"notes": data.notes, "updated_at": updated})
    with db() as conn:
        out = conn.execute("SELECT * FROM proofs WHERE proof_id=?", (proof_id,)).fetchone()
    return dict(out)


def project_event(data: MembraEventIn) -> list[dict[str, Any]]:
    event_payload = data.model_dump()
    proof = create_proof_record(
        ProofIn(
            subject_type=data.subject_type,
            subject_id=data.subject_id,
            owner_email="",
            proof_type=f"membra_event:{data.event_type}",
            evidence_url="",
            consent_scope=data.consent_scope or "canonical MEMBRA event envelope and proof hash only",
            reviewer="event_ingest",
            metadata={"event": event_payload},
        )
    )
    record_audit(proof["proof_id"], "event_envelope_ingested", data.source_module, event_payload)
    return [{"table": "proofs", "id": proof["proof_id"]}]


def proof_rows() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT proof_id,subject_type,subject_id,proof_type,proof_hash,status,reviewer,created_at,updated_at FROM proofs ORDER BY created_at DESC LIMIT 250").fetchall()
    return [dict(r) for r in rows]


def audit_rows() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 500").fetchall()
    return [dict(r) for r in rows]


def event_rows() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY ingested_at DESC LIMIT 500").fetchall()
    return [dict(r) for r in rows]


def export_proofs() -> str:
    path = "/tmp/membra_proofbook_audit.csv"
    proof_data = proof_rows()
    if proof_data:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(proof_data[0].keys()))
            writer.writeheader(); writer.writerows(proof_data)
    else:
        Path(path).write_text("proof_id,subject_type,subject_id,status\n", encoding="utf-8")
    return path


@api.get("/api/health")
def health():
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION, "policy": "hashes and consented metadata only"}


@api.get("/api/ready")
def ready():
    warnings = [] if MEMBRA_EVENT_SECRET else ["MEMBRA_EVENT_SECRET not configured; signed event verification is permissive"]
    return {"ok": True, "warnings": warnings, "proof_count": len(proof_rows()), "event_count": len(event_rows())}


@api.post("/api/events/ingest")
def ingest_event(data: MembraEventIn):
    event = data.model_dump()
    if not verify_event_signature(event):
        raise HTTPException(401, "invalid event signature")
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (data.event_id, data.event_type, data.source_module, data.subject_type, data.subject_id, data.owner_id, data.risk_level, data.proof_hash, data.signature, json.dumps(event, default=str), "ingested", data.created_at, now()),
        )
    projections = project_event(data)
    return {"ok": True, "event_id": data.event_id, "projections": projections}


@api.get("/api/events")
def list_events():
    return {"events": event_rows()}


@api.post("/api/proofs")
def create_proof(data: ProofIn):
    return create_proof_record(data)


@api.post("/api/proofs/{proof_id}/review")
def review_proof(proof_id: str, data: ReviewIn):
    return review_record(proof_id, data)


@api.get("/api/proofs")
def list_proofs():
    return {"proofs": proof_rows()}


@api.get("/api/audit-events")
def list_audit():
    return {"audit_events": audit_rows()}


def ui_submit(subject_type, subject_id, owner_email, proof_type, evidence_url, consent_scope, metadata_json):
    try:
        meta = json.loads(metadata_json or "{}")
        proof = create_proof_record(ProofIn(subject_type=subject_type, subject_id=subject_id, owner_email=owner_email, proof_type=proof_type, evidence_url=evidence_url, consent_scope=consent_scope, metadata=meta))
        return proof, proof_rows(), audit_rows(), export_proofs()
    except Exception as exc:
        return {"error": str(exc)}, proof_rows(), audit_rows(), None


def ui_review(proof_id, status, reviewer, notes):
    try:
        out = review_record(proof_id, ReviewIn(status=status, reviewer=reviewer, notes=notes))
        return out, proof_rows(), audit_rows(), export_proofs()
    except Exception as exc:
        return {"error": str(exc)}, proof_rows(), audit_rows(), None


with gr.Blocks(title=APP_NAME) as demo:
    gr.Markdown("# MEMBRA ProofBook\nVerifiable proof ledger and canonical event receiver. Stores hashes and consented metadata only.")
    with gr.Tab("Submit proof"):
        subject_type = gr.Dropdown(["asset", "listing", "campaign", "wear_kit", "relay_job", "artifact", "wallet_event"], value="asset", label="Subject type")
        subject_id = gr.Textbox(label="Subject ID")
        owner_email = gr.Textbox(label="Owner email")
        proof_type = gr.Textbox(label="Proof type", value="photo_timestamp_metadata")
        evidence_url = gr.Textbox(label="Evidence URL")
        consent_scope = gr.Textbox(label="Consent scope", value="public hash, timestamp, proof metadata, and review status only")
        metadata_json = gr.Code(label="Metadata JSON", language="json", value="{}")
        submit = gr.Button("Submit proof", variant="primary")
        proof_out = gr.JSON(label="Proof record")
    with gr.Tab("Review"):
        review_id = gr.Textbox(label="Proof ID")
        review_status = gr.Dropdown(["approved", "rejected", "needs_more_evidence", "fraud_hold", "archived"], value="approved", label="Status")
        reviewer = gr.Textbox(label="Reviewer", value="operator")
        notes = gr.Textbox(label="Review notes", lines=3)
        review_btn = gr.Button("Record review", variant="primary")
        review_out = gr.JSON(label="Review result")
    with gr.Tab("Events"):
        gr.Markdown("Canonical MEMBRA events arrive through `/api/events/ingest`.")
        events_table = gr.Dataframe(label="Event envelopes", value=event_rows, interactive=False)
    proofs_table = gr.Dataframe(label="Proof register", value=proof_rows, interactive=False)
    audit_table = gr.Dataframe(label="Audit events", value=audit_rows, interactive=False)
    export_file = gr.File(label="Proof CSV export")
    submit.click(ui_submit, [subject_type, subject_id, owner_email, proof_type, evidence_url, consent_scope, metadata_json], [proof_out, proofs_table, audit_table, export_file])
    review_btn.click(ui_review, [review_id, review_status, reviewer, notes], [review_out, proofs_table, audit_table, export_file])

app = gr.mount_gradio_app(api, demo, path="/")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "7860")))
