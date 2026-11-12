# KernLock Security — Threat Intelligence Key Custody and Rotation Guide

This document describes the cryptographic operational procedures for signing, distributing, and rotating KernLock Threat Intelligence update bundles.

---

## 1. Threat Intelligence Cryptographic Architecture

KernLock utilizes the Ed25519 digital signature scheme (RFC 8032) for authenticating threat definition bundles:
- **Pinned Public Key**: The official KernLock public key (`69d50c0ac704c7d545b942deb8427f610a0611e1a5194cc09d0f5ffd9a71d181`) is baked into `kernlock-core`.
- **Private Key Custody**: The private signing key **MUST NEVER** be committed to source control or stored on Internet-connected builder machines.
- **Strict Verification**: Every bundle must verify strictly against explicitly pinned or enterprise-configured trusted public keys. Self-supplied or untrusted keys are unconditionally rejected.
- **Anti-Rollback**: Both semantic version and manifest publication timestamps are enforced monotonically. Definitions cannot be downgraded to vulnerable past versions.

---

## 2. Generating an Offline Signing Keypair

Run the KernLock CLI on an air-gapped security workstation:

```bash
kernlock generate-signing-key \
    --out-priv-key /secure/offline/threat_signing_priv.key \
    --out-pub-key /secure/offline/threat_signing_pub.key
```

- The private key file is created with restrictive permissions (`chmod 0600`).
- The 32-byte hex public key can be safely shared and pinned in deployment configurations.

---

## 3. Offline Bundle Signing Procedure

1. Prepare your `manifest.json` describing detection rules, hash signatures, and byte signatures:
   ```json
   {
     "version": "2026.11.2",
     "timestamp": "2026-11-12T20:00:00Z",
     "rules": [...],
     "hash_signatures": [...],
     "byte_signatures": [...]
   }
   ```

2. Sign the bundle offline using the private key:
   ```bash
   kernlock sign-bundle \
       --manifest manifest.json \
       --key-file /secure/offline/threat_signing_priv.key \
       --output signed_bundle_v2026.11.2.json
   ```

3. Deploy `signed_bundle_v2026.11.2.json` to the update distribution server or ingest it into running daemons via the API:
   ```bash
   curl -X POST http://127.0.0.1:17420/api/v1/definitions/update \
       -H "Authorization: Bearer <AUTH_TOKEN>" \
       -H "Content-Type: application/json" \
       -d @signed_bundle_v2026.11.2.json
   ```

---

## 4. Key Rotation Protocol

To rotate the signing key:
1. **Air-Gapped Key Generation**: Generate a new Ed25519 keypair on an air-gapped machine.
2. **Transition Window**: Enterprise environments can add the new public key using `engine.add_trusted_key_hex("<NEW_PUBKEY_HEX>")` or via configuration files.
3. **Signed Cross-Certification**: Release a final bundle signed by the active key containing an enterprise key update directive.
4. **Code Update**: In future major/minor releases, update `OFFICIAL_PUBLIC_KEY_HEX` in `crates/kernlock-core/src/intelligence.rs`.
5. **Key Retirement**: Revoke and archive the old private key in cold storage.
