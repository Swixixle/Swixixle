# ELI-Sentinel Verification Protocol

## Overview

The ELI-Sentinel verification protocol provides tamper-evident, independently verifiable receipts for AI transactions using:

1. **Canonical JSON (json_c14n_v1)** - Deterministic serialization
2. **HALO Chain (halo_v1)** - Hash-anchored integrity chain
3. **RSA Signatures** - Cryptographic non-repudiation

---

## 1. Canonical JSON (json_c14n_v1)

### Purpose

Ensure that the same data structure **always** produces the **exact same bytes**, enabling reliable hashing and verification.

### Rules

1. **UTF-8 encoding** - All text encoded as UTF-8
2. **Objects** - Keys sorted lexicographically
3. **Arrays** - Order preserved as-is
4. **No whitespace** - No spaces, tabs, or newlines
5. **Reject NaN/Infinity** - Strict IEEE 754 compliance
6. **Stable strings** - Unicode characters preserved (not ASCII-escaped)

### Example

Input:
```python
{"z": "last", "a": "first", "nested": {"b": 2, "a": 1}}
```

Canonical output:
```json
{"a":"first","nested":{"a":1,"b":2},"z":"last"}
```

### Implementation

```python
from gateway.app.services.c14n import json_c14n_v1

canonical_bytes = json_c14n_v1(obj)
sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()
```

### Test Vectors

See `tests/canonicalization_vectors.json` for fixed test cases with expected SHA256 hashes.

---

## 2. HALO Chain (halo_v1)

### Purpose

Create a tamper-evident chain where:
- Each block depends on the previous block
- Any change to any field invalidates the entire chain
- Verification is deterministic and offline-capable

### Structure

The HALO chain consists of 5 blocks:

#### Block 1: Core Transaction Identifiers
```json
{
  "transaction_id": "tx_...",
  "gateway_timestamp_utc": "2024-01-01T00:00:00Z",
  "environment": "production",
  "client_id": "client_abc"
}
```

#### Block 2: Intent and Context
```json
{
  "previous_hash": "<block_1_hash>",
  "intent_manifest": "chat_completion",
  "feature_tag": "gpt4",
  "user_ref": "user_123"
}
```

#### Block 3: Input Hashes
```json
{
  "previous_hash": "<block_2_hash>",
  "prompt_hash": "sha256:...",
  "rag_hash": "sha256:...",
  "multimodal_hash": "sha256:..."
}
```

#### Block 4: Policy and Model Metadata
```json
{
  "previous_hash": "<block_3_hash>",
  "policy_receipt_subset": {
    "policy_version_hash": "sha256:...",
    "approved": true,
    "policy_change_ref": "pcr_1"
  },
  "model_fingerprint": "gpt-4-0613",
  "param_snapshot": {"temperature": 0.7}
}
```

#### Final Hash: Output and Metrics
```json
{
  "previous_hash": "<block_4_hash>",
  "output_hash": "sha256:...",
  "token_usage": {"prompt": 50, "completion": 100},
  "latency_ms": 1234
}
```

**Note**: For denied transactions, `output_hash` is `null`, but the final hash is still computed.

### Computation

Each block is:
1. Canonicalized using `json_c14n_v1`
2. Hashed with SHA256
3. Prefixed with `"sha256:"` for the hash format

```python
from gateway.app.services.halo import compute_halo_chain

halo_chain = compute_halo_chain(packet_data)
# Returns: {block_1, block_2, block_3, block_4, final_hash}
```

### Verification

To verify a HALO chain:
1. Recompute all blocks from the packet data
2. Compare computed hashes with stored hashes
3. If **any** hash mismatches, the packet is invalid

```python
from gateway.app.services.halo import verify_halo_chain

report = verify_halo_chain(packet)
# Returns: {valid, failures, verified_blocks}
```

### Properties

- **Chaining**: Modifying block N invalidates all subsequent blocks
- **Determinism**: Same input always produces same chain
- **Completeness**: All transaction data is covered by the chain

### Test Vectors

See `tests/test_halo_chain.py` for fixed test cases with known hash values.

---

## 3. Cryptographic Signature

### Purpose

Provide **non-repudiation**: Prove that the gateway created and signed this specific receipt.

### Signed Message

The gateway signs the **canonical JSON** of:

```json
{
  "transaction_id": "tx_...",
  "gateway_timestamp_utc": "2024-01-01T00:00:00Z",
  "final_hash": "sha256:...",
  "policy_version_hash": "sha256:...",
  "client_key_fingerprint": "sha256:..."
}
```

This message contains:
- Transaction identity
- HALO chain summary (final_hash)
- Policy reference
- Client identity

### Signature Algorithm

- **Algorithm**: RSA with PKCS1v15 padding
- **Hash**: SHA256
- **Key size**: 2048 bits (minimum)
- **Format**: JWK (JSON Web Key)

### Signature Storage

Stored in packet under `verification.signature`:

```json
{
  "alg": "RS256",
  "key_id": "sha256:...",
  "signature_b64": "<base64-encoded-signature>"
}
```

### Public Key Distribution

Public keys are served via:
- `GET /v1/keys` - List all active keys
- `GET /v1/keys/{key_id}` - Get specific key as JWK

### Verification

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Reconstruct signed message
signed_message = {
    "transaction_id": packet["transaction_id"],
    "gateway_timestamp_utc": packet["gateway_timestamp_utc"],
    "final_hash": packet["halo_chain"]["final_hash"],
    "policy_version_hash": packet["policy_receipt_subset"]["policy_version_hash"],
    "client_key_fingerprint": packet["client_key_fingerprint"]
}

# 2. Canonicalize
message_bytes = json_c14n_v1(signed_message)

# 3. Load public key from JWK
# (Convert n, e from base64url to RSA public key)

# 4. Verify signature
public_key.verify(
    signature_bytes,
    message_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)
```

### Key Rotation

For production:
- Multiple keys can be active simultaneously
- `key_id` in signature identifies which key to use
- Old keys should remain available for verifying historical receipts

---

## 4. Complete Packet Structure

A complete transaction receipt packet:

```json
{
  "transaction_id": "tx_...",
  "gateway_timestamp_utc": "2024-01-01T00:00:00Z",
  "environment": "production",
  "client_id": "client_abc",
  "intent_manifest": "chat_completion",
  "feature_tag": "gpt4",
  "user_ref": "user_123",
  
  "prompt_hash": "sha256:...",
  "rag_hash": "sha256:...",
  "multimodal_hash": null,
  
  "policy_receipt_subset": {
    "policy_version_hash": "sha256:...",
    "approved": true,
    "policy_change_ref": "pcr_1"
  },
  
  "model_fingerprint": "gpt-4-0613",
  "param_snapshot": {"temperature": 0.7},
  
  "output_hash": "sha256:...",
  "token_usage": {"prompt": 50, "completion": 100},
  "latency_ms": 1234,
  
  "client_key_fingerprint": "sha256:...",
  
  "halo_chain": {
    "block_1": "sha256:...",
    "block_2": "sha256:...",
    "block_3": "sha256:...",
    "block_4": "sha256:...",
    "final_hash": "sha256:..."
  },
  
  "verification": {
    "signature": {
      "alg": "RS256",
      "key_id": "sha256:...",
      "signature_b64": "..."
    }
  }
}
```

---

## 5. Verification Process

### Step 1: Schema Validation

Ensure all required fields are present:
- `transaction_id`
- `gateway_timestamp_utc`
- `environment`
- `client_id`
- `halo_chain` (with all 5 blocks)

**Exit code**: 10 if schema invalid

### Step 2: HALO Chain Verification

1. Extract packet data
2. Recompute all 5 blocks
3. Compare with stored hashes
4. Report any mismatches

**Exit code**: 2 if HALO chain invalid

### Step 3: Signature Verification

1. Fetch public key (from file or endpoint)
2. Reconstruct signed message
3. Verify signature
4. Check signature algorithm matches

**Exit code**: 3 if signature invalid
**Exit code**: 4 if key fetch failed

### Step 4: Report

If all checks pass:
- Exit code: 0
- Status: VALID

If any check fails:
- List all failures
- Exit with appropriate code

---

## 6. Security Properties

### What We Prove

1. **Integrity**: Packet has not been modified since creation
2. **Non-repudiation**: Gateway signed this specific packet
3. **Completeness**: All transaction data is covered by HALO chain
4. **Ordering**: Blocks are chained in correct sequence

### What We DON'T Prove

1. **Truthfulness**: Gateway could lie about what happened
2. **Completeness of inputs**: Only hashes are stored, not full content
3. **Authorization**: Does not verify if client was authorized
4. **Freshness**: Timestamp is not independently verified

### Threat Model

**Protected against**:
- Tampering with packet data
- Forging receipts without private key
- Reordering or removing blocks

**NOT protected against**:
- Compromised private key
- Gateway misbehavior (recording wrong data)
- Replay attacks (requires additional timestamp verification)

---

## 7. Comparison to Other Approaches

### vs. Simple Hashing

❌ Simple hash of entire packet
- ✓ Detects tampering
- ✗ Can't identify which field was tampered
- ✗ No structure, no incremental verification

✅ HALO chain
- ✓ Detects tampering
- ✓ Identifies which block failed
- ✓ Structured, allows partial verification

### vs. Merkle Trees

❌ Merkle tree over fields
- ✓ Efficient batch verification
- ✗ No sequential ordering
- ✗ Requires more complex verification logic

✅ HALO chain
- ✓ Sequential ordering enforced
- ✓ Simple verification (just recompute)
- ✓ Human-readable structure

### vs. Blockchain

❌ Full blockchain
- ✓ Decentralized verification
- ✗ Requires consensus mechanism
- ✗ High overhead, not suitable for high-volume

✅ HALO + Signatures
- ✓ Centralized but verifiable
- ✓ No consensus needed
- ✓ High performance, suitable for real-time

---

## 8. Implementation Notes

### Performance

- **Canonicalization**: ~10μs per object (Python)
- **SHA256**: ~1μs per hash
- **RSA signing**: ~1ms (2048-bit key)
- **Total overhead**: <5ms per transaction

### Storage

- **Packet size**: ~2-4KB (without actual content)
- **HALO chain**: 5 × 71 bytes = 355 bytes
- **Signature**: ~256 bytes (base64)

### Optimization

For high-volume production:
1. Batch hash computations
2. Pre-compute policy hashes
3. Use faster crypto library (e.g., PyNaCl for Ed25519)
4. Cache canonicalization results

---

## 9. Future Extensions

### Content Storage

Add optional content storage with references:
```json
{
  "prompt_hash": "sha256:...",
  "prompt_ref": "s3://bucket/prompts/sha256:...",
  "prompt_encrypted": true
}
```

### Multi-Signature

Support multiple signers (e.g., auditor co-signs):
```json
{
  "verification": {
    "gateway_signature": {...},
    "auditor_signature": {...}
  }
}
```

### Time-Stamping

Add trusted timestamp authority:
```json
{
  "verification": {
    "signature": {...},
    "timestamp": {
      "tsa_url": "...",
      "timestamp_token": "..."
    }
  }
}
```

---

## 10. Test Vectors

All test vectors are in the `tests/` directory:

- **Canonicalization**: `tests/canonicalization_vectors.json`
- **HALO Chain**: `tests/test_halo_chain.py` (fixed vector in `test_fixed_vector_1`)

To regenerate test vectors:
```bash
pytest tests/test_c14n_vectors.py -v
pytest tests/test_halo_chain.py -v
```

---

## References

- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 7517 - JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 8017 - PKCS #1: RSA Cryptography](https://www.rfc-editor.org/rfc/rfc8017)

---

> Verification is not about trust. It's about math.
