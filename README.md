# Membra ProofBook

**Membra ProofBook is the verification ledger namespace for MEMBRA Labs and the MEMBRA Proof Network.**

It records canonical proof events, hashes, audit trails, QR/NFC interactions, campaign proof, reward eligibility, payout status, and optional Devnet anchors.

## Company Context

- Company: **MEMBRA Labs**
- Flagship product: **MEMBRA Proof Network**
- Module: **Membra ProofBook**
- Category: proof ledger, audit trail, canonical event hashing, verified reports

## One-Line Thesis

If MEMBRA claims a campaign placement, scan, proof event, media kit, or reward state happened, ProofBook makes that claim reproducible and auditable.

## Product Role

ProofBook is the evidence layer behind MEMBRA Proof Network.

It should store or reference:

- proof-event metadata
- canonical JSON payloads
- SHA-256 hashes
- source system identifiers
- timestamps
- review status
- scan/tap records
- reward eligibility records
- payout/release records
- optional Devnet anchor IDs

## ProofBook Event Types

- `owner_created`
- `advertiser_created`
- `asset_registered`
- `asset_verified`
- `campaign_created`
- `creative_approved`
- `campaign_funded`
- `media_kit_created`
- `qr_scan`
- `nfc_tap`
- `proof_submitted`
- `proof_reviewed`
- `reward_eligible`
- `reward_released`
- `vendor_order_created`
- `kit_delivered`

## Canonical Proof Process

1. Receive source event.
2. Normalize payload into canonical JSON.
3. Compute SHA-256 hash.
4. Store payload, hash, source, and status.
5. Optionally anchor hash through Devnet utilities.
6. Return proof ID and proof hash.

## Integration Points

| Repo | ProofBook Relationship |
|---|---|
| `overandor/Membra_ads` | campaign, media-kit, scan, proof, and audit events |
| `overandor/Membra_wallet` | funding, reward eligibility, payout release hashes |
| `overandor/Membra_admin-` | proof review and manual override audit trail |
| `overandor/Membra_contracts` | optional Devnet proof-anchor utilities |
| `overandor/membra-qr-gateway` | public/private proof timeline display |
| `overandor/Membra_kpi` | verified report source and audit exports |
| `overandor/Membra_mobile` | owner-submitted proof metadata |

## Rules

- store evidence metadata, not sensitive raw identity data
- hashes must be reproducible from canonical JSON
- every proof event should have a source system
- failed events should remain recorded with failure status
- Devnet anchoring is optional and must not replace the database
- no raw KYC documents in public proof views
- no payout eligibility without proof status traceability

## Productization Priority

ProofBook should become the shared audit layer once the Membra Ads workflow and QR Gateway demo are connected.

## Current Stage

Verification module scaffold and proof-ledger charter. Suitable for company packaging; not yet a complete production ledger.