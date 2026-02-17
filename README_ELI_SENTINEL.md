# ELI-Sentinel

**AI Governance Gateway** that produces tamper-evident, signed transaction receipts for every AI call.

## What It Does

ELI-Sentinel is a FastAPI service + offline verifier CLI that provides:

1. **Tamper-evident receipts** using HALO (Hash-Anchored Layered Operands) chain
2. **Cryptographic signatures** (RSA + JWK) for independent verification
3. **Policy governance** with SOX-grade approval workflows
4. **Offline verification** via portable CLI tool

This is **not** a dashboard. It's a verification protocol for AI governance.

---

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 -c "from gateway.app.models.database import init_db; init_db()"
```

### Start the Gateway

```bash
# From project root
python3 -m uvicorn gateway.app.main:app --host 0.0.0.0 --port 8000
```

The gateway will:
- Generate RSA keypair in `gateway/.keys/` (first run)
- Create SQLite database in `gateway/data/`
- Expose API at http://localhost:8000

---

## Core Workflow

### 1. Activate a Policy

```bash
# Propose policy
curl -X POST http://localhost:8000/v1/policies/proposals \
  -H "Content-Type: application/json" \
  -d '{
    "environment": "production",
    "policy_logic": {
      "version": "1.0",
      "rules": [
        {"condition": {"client_id": "allowed"}, "action": "approve"}
      ]
    },
    "proposer": "alice",
    "reason": "Initial policy",
    "ticket_ref": "JIRA-123"
  }'

# Returns: {"proposal_id": 1, "policy_version_hash": "sha256:...", ...}

# Approve policy (different user in production)
curl -X POST http://localhost:8000/v1/policies/proposals/1/approve \
  -H "Content-Type: application/json" \
  -d '{"approver": "bob"}'
```

### 2. Make an AI Call

```bash
curl -X POST http://localhost:8000/v1/ai/call \
  -H "Content-Type: application/json" \
  -d '{
    "environment": "production",
    "client_id": "client_abc",
    "intent_manifest": "chat_completion",
    "feature_tag": "gpt4",
    "user_ref": "user_123",
    "prompt": "What is the capital of France?",
    "model_fingerprint": "gpt-4-0613",
    "parameters": {"temperature": 0.7, "max_tokens": 100}
  }' > transaction_receipt.json
```

Response includes:
- `transaction_id`: Unique transaction ID
- `approved`: Boolean approval status
- `output`: AI response (or null if denied)
- `receipt`: Complete tamper-evident packet

### 3. Verify the Receipt Offline

```bash
# With local JWK file
python3 tools/eli_verify.py transaction_receipt.json --jwk public_key.jwk

# Or fetch key from gateway
python3 tools/eli_verify.py transaction_receipt.json \
  --keys-url http://localhost:8000/v1/keys

# Machine-readable output
python3 tools/eli_verify.py transaction_receipt.json --jwk key.jwk --json
```

The verifier checks:
- ✓ Schema validation
- ✓ HALO chain integrity (5-block hash chain)
- ✓ Cryptographic signature

---

## HALO Chain Structure

Each transaction receipt contains a 5-block hash chain:

- **block_1**: Core identifiers (transaction_id, timestamp, environment, client_id)
- **block_2**: Intent context (intent_manifest, feature_tag, user_ref)
- **block_3**: Input hashes (prompt_hash, rag_hash, multimodal_hash)
- **block_4**: Policy & model (policy_receipt, model_fingerprint, parameters)
- **final_hash**: Output & metrics (output_hash, token_usage, latency_ms)

Each block includes the previous block's hash, creating a tamper-evident chain.

---

## API Endpoints

### Verification

- `GET /v1/keys` - List active signing keys
- `GET /v1/keys/{key_id}` - Get public JWK for verification

### Policy Management

- `POST /v1/policies/proposals` - Propose policy change
- `POST /v1/policies/proposals/{id}/approve` - Approve proposal
- `POST /v1/policies/proposals/{id}/reject` - Reject proposal
- `GET /v1/policies/active?environment=prod` - Get active policy
- `GET /v1/policies/changes?environment=prod` - List change requests

### Transactions

- `POST /v1/ai/call` - Execute AI call through gateway
- `GET /v1/transactions/{id}` - Retrieve transaction receipt
- `POST /v1/transactions/{id}/verify` - Server-side verification

---

## Offline Verifier CLI

### Usage

```bash
python3 tools/eli_verify.py <packet.json> [options]

Options:
  --jwk PATH           Path to JWK file for signature verification
  --keys-url URL       URL to keys endpoint for fetching JWK
  --skip-signature     Skip signature verification (HALO only)
  --json               Output results as JSON
```

### Exit Codes

- `0` - Valid transaction
- `2` - HALO chain verification failed
- `3` - Signature verification failed
- `4` - Key fetch failed
- `10` - Schema validation failed

### Portability

The verifier (`tools/eli_verify.py`) is a **single-file, standalone tool** with embedded canonicalization and HALO verification logic. It can be distributed separately and requires only:

- Python 3.7+
- `cryptography` library (for signature verification)

---

## Testing

### Run Tests

```bash
# Canonicalization tests (11 tests)
pytest tests/test_c14n_vectors.py -v

# HALO chain tests (10 tests)
pytest tests/test_halo_chain.py -v

# All tests
pytest tests/ -v
```

### Test Vectors

Fixed test vectors ensure:
- Canonical JSON produces exact bytes and SHA256 hashes
- HALO chain hashes are deterministic
- Tampering is detected

---

## Architecture

```
eli-sentinel/
├── gateway/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── models/
│   │   │   └── database.py      # SQLAlchemy models
│   │   ├── routes/
│   │   │   ├── policies.py      # Policy management
│   │   │   └── transactions.py  # AI call transactions
│   │   └── services/
│   │       ├── c14n.py          # Canonical JSON
│   │       ├── halo.py          # HALO hash chain
│   │       ├── policy.py        # Policy hashing
│   │       └── signer.py        # RSA signature service
│   ├── data/                    # SQLite database
│   └── .keys/                   # RSA keypair (dev only)
├── tools/
│   └── eli_verify.py            # Offline verifier CLI
├── tests/
│   ├── canonicalization_vectors.json
│   ├── test_c14n_vectors.py
│   └── test_halo_chain.py
└── docs/
```

---

## Security Model

### What's Protected

- **Packet integrity**: HALO chain detects any tampering
- **Non-repudiation**: RSA signature proves gateway created receipt
- **Policy audit trail**: Content-addressed policies with approval workflow

### What's NOT Protected (by design)

- **Input/output confidentiality**: Hashes are stored, not content (add encryption separately)
- **Network security**: Use TLS in production
- **Key management**: Local keys are dev-only (use KMS in production)

---

## Production Considerations

### Before Production

1. **Replace local keys** with KMS (AWS KMS, Azure Key Vault, etc.)
   - Update `gateway/app/services/signer.py`
   - Interface remains the same

2. **Use PostgreSQL** instead of SQLite
   - Schema is designed to map cleanly
   - Update connection string in `database.py`

3. **Enable TLS/HTTPS** for API
   - Protect keys endpoint
   - Secure policy approval workflow

4. **Implement real policy evaluation**
   - Current implementation auto-approves
   - Add rule engine in `transactions.py`

5. **Add authentication**
   - API key validation
   - Client identity verification

---

## Design Principles

1. **Evidence before interpretation** - Store facts, not conclusions
2. **Cryptography before policy** - Verify first, interpret later
3. **Offline verification** - No dependency on running service
4. **Fail loudly** - Tampered receipts are rejected, not tolerated
5. **Content-addressed everything** - Policies, inputs, outputs by hash

---

## License

MIT

---

## Support

For questions or issues:
- Review `docs/verification.md` for technical details
- Check test files for examples
- Inspect sample packets for structure

---

> **This is infrastructure for systems that must be argued about after they exist.**
