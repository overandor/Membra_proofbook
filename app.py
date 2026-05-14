"""MEMBRA ProofBook — verifiable proof ledger and audit trail.

ProofBook records public hashes, evidence metadata, consent scope, review status,
and exportable audit trails. It does not store raw private memories, private keys,
seed phrases, or unconsented personal material.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
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
APP_VERSION = "1.0.0"
DB_PATH = Path(os.getenv("APP_DB_PATH", "/tmp/membra_proofbook.sqlite3"))
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


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


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


def proof_rows() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT proof_id,subject_type,subject_id,proof_type,proof_hash,status,reviewer,created_at,updated_at FROM proofs ORDER BY created_at DESC LIMIT 250").fetchall()
    return [dict(r) for r in rows]


def audit_rows() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 500").fetchall()
    return [dict(r) for r in rows]


def export_proofs() -> str:
    path = "/tmp/membra_proofbook_audit.csv"
    rows = proof_rows()
    if rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader(); writer.writerows(rows)
    else:
        Path(path).write_text("proof_id,subject_type,subject_id,status\n", encoding="utf-8")
    return path

@api.get("/api/health")
def health():
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION, "policy": "hashes and consented metadata only"}

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
    gr.Markdown("# MEMBRA ProofBook\nVerifiable proof ledger for assets, campaigns, wear kits, relay jobs, artifacts, and payout eligibility. Stores hashes and consented metadata only.")
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
    proofs_table = gr.Dataframe(label="Proof register", value=proof_rows, interactive=False)
    audit_table = gr.Dataframe(label="Audit events", value=audit_rows, interactive=False)
    export_file = gr.File(label="Proof CSV export")
    submit.click(ui_submit, [subject_type, subject_id, owner_email, proof_type, evidence_url, consent_scope, metadata_json], [proof_out, proofs_table, audit_table, export_file])
    review_btn.click(ui_review, [review_id, review_status, reviewer, notes], [review_out, proofs_table, audit_table, export_file])

app = gr.mount_gradio_app(api, demo, path="/")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "7860")))
