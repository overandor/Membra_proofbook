# MEMBRA Protocol

Membra_api is the system of record for canonical owners, advertisers, assets, campaigns, placements, proof records, payout states, auth, and analytics APIs.

This repo follows the shared Membra protocol for proof hashing, audit verification, immutable proof snapshots, and proof report validation.

Core invariant: verified owner creates verified asset; approved creative creates media kit; certified QR/NFC identity creates placement; approved proof creates payout eligibility; audit events back every trusted state change.

Required shared IDs: own_, adv_, ast_, cmp_, plc_, kit_, qr_, nfc_, proof_, scan_, tap_, pay_, pout_, aud_, snap_.

ProofBook rule: proof snapshots are derived from canonical API records and must not create conflicting source-of-truth state.
