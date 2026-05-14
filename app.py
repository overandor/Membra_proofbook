from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

APP_NAME = os.getenv('APP_NAME', 'Membra ProofBook')
APP_VERSION = '0.1.0'
DB_PATH = Path(os.getenv('APP_DB_PATH', 'membra_proofbook.db'))

app = FastAPI(title=APP_NAME, version=APP_VERSION)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f'{prefix}_{uuid.uuid4().hex[:16]}'


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(payload).encode('utf-8')).hexdigest()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS entries (id TEXT PRIMARY KEY, event_type TEXT, source_system TEXT, source_id TEXT, data_json TEXT, data_hash TEXT, status TEXT, external_ref TEXT, created_at TEXT)')


@app.on_event('startup')
def startup() -> None:
    init_db()


class EntryCreate(BaseModel):
    event_type: str
    source_system: str = 'membra'
    source_id: str | None = None
    data: dict[str, Any]
    status: str = 'recorded'


class ExternalRefUpdate(BaseModel):
    external_ref: str
    status: str = 'referenced'


@app.get('/v1/health')
def health() -> dict[str, Any]:
    return {'ok': True, 'app': APP_NAME, 'version': APP_VERSION}


@app.post('/v1/entries')
def create_entry(req: EntryCreate) -> dict[str, Any]:
    entry_id = new_id('entry')
    h = digest(req.data)
    with db() as conn:
        conn.execute('INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (entry_id, req.event_type, req.source_system, req.source_id, canonical(req.data), h, req.status, None, now_iso()))
    return {'entry_id': entry_id, 'data_hash': h, 'status': req.status}


@app.get('/v1/entries')
def list_entries(limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    with db() as conn:
        rows = conn.execute('SELECT * FROM entries ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
    return {'entries': [dict(r) for r in rows]}


@app.get('/v1/entries/{entry_id}')
def get_entry(entry_id: str) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute('SELECT * FROM entries WHERE id=?', (entry_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'entry not found')
    return dict(row)


@app.post('/v1/entries/{entry_id}/external-ref')
def set_external_ref(entry_id: str, req: ExternalRefUpdate) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute('SELECT id FROM entries WHERE id=?', (entry_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'entry not found')
        conn.execute('UPDATE entries SET external_ref=?, status=? WHERE id=?', (req.external_ref, req.status, entry_id))
    return {'entry_id': entry_id, 'status': req.status, 'external_ref': req.external_ref}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=int(os.getenv('PORT', '8000')))
