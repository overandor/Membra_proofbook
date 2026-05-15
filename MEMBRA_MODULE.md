# MEMBRA Module Contract — ProofBook

## Role

Proof hash ledger for MEMBRA. Records proof hashes, consent scope, evidence metadata, review status, audit events, and exportable proof registers.

## System inputs

- proof submissions
- evidence references
- consent scope
- reviewer decisions
- subject IDs from KPI, ads, wear, relay, QR, wallet, and API modules

## System outputs

- proof records
- audit records
- proof hashes
- review status
- CSV audit exports

## Health

```text
GET /api/health
```

## Replit role

`service`

Runs as a trust/audit service for the MEMBRA OS workspace.

## Production boundary

Stores hashes and consented metadata only. Does not store private keys, seed phrases, raw private memories, or unconsented material.
