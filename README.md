# Membra ProofBook

Membra ProofBook is the verification ledger for the MEMBRA ecosystem.

It records canonical proof events, hashes, audit trails, QR/NFC interactions, campaign proof, reward eligibility, and optional Devnet anchors.

## One-line thesis

If MEMBRA claims a campaign placement, scan, proof event, media kit, or reward state happened, ProofBook makes that claim reproducible and auditable.

## Role in the ecosystem

- `Membra_api` creates operational records.
- `Membra_ads` creates campaign and media-kit events.
- `Membra_mobile` submits proof media metadata.
- `membra-qr-gateway` displays proof timelines.
- `Membra_wallet` records funding and reward-state events.
- `Membra_contracts` can anchor proof hashes in Devnet-first mode.

## ProofBook event types

- owner_created
- advertiser_created
- asset_registered
- asset_verified
- campaign_created
- creative_approved
- campaign_funded
- media_kit_created
- qr_scan
- nfc_tap
- proof_submitted
- proof_reviewed
- reward_eligible
- reward_released
- vendor_order_created
- kit_delivered

## Canonical proof process

1. Receive source event.
2. Normalize payload into canonical JSON.
3. Compute SHA-256 hash.
4. Store payload, hash, source, and status.
5. Optionally anchor hash through Devnet utilities.
6. Return proof id and proof hash.

## Rules

- ProofBook stores evidence metadata, not sensitive raw identity data.
- Hashes must be reproducible from canonical JSON.
- Every proof event should have a source system.
- Failed events should remain recorded with failure status.
- Devnet anchoring is optional and must not replace the database.

## Current stage

Verification module scaffold with standalone FastAPI starter.
