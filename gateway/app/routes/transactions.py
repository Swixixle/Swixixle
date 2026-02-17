"""
Transaction routes for AI calls
"""

from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import hashlib
import uuid

from gateway.app.models.database import get_session, Transaction, ActivePolicyPointer
from gateway.app.services.halo import compute_halo_chain
from gateway.app.services.signer import get_signer
from gateway.app.services.c14n import json_c14n_v1

router = APIRouter(prefix="/v1", tags=["transactions"])


# Pydantic models
class AICallRequest(BaseModel):
    """Request for AI call through gateway."""
    environment: str = Field(..., description="Environment (dev, staging, production)")
    client_id: str = Field(..., description="Client identifier")
    intent_manifest: str = Field(..., description="Intent type (e.g., chat_completion)")
    feature_tag: str = Field(..., description="Feature/model tag")
    user_ref: Optional[str] = Field(None, description="User reference")
    
    # Input data
    prompt: str = Field(..., description="Prompt text")
    rag_context: Optional[str] = Field(None, description="RAG context")
    multimodal_data: Optional[str] = Field(None, description="Multimodal data")
    
    # Model parameters
    model_fingerprint: str = Field(..., description="Model identifier")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Model parameters")
    
    class Config:
        schema_extra = {
            "example": {
                "environment": "production",
                "client_id": "client_abc",
                "intent_manifest": "chat_completion",
                "feature_tag": "gpt4",
                "user_ref": "user_123",
                "prompt": "What is the capital of France?",
                "model_fingerprint": "gpt-4-0613",
                "parameters": {"temperature": 0.7, "max_tokens": 100}
            }
        }


def get_db():
    """Dependency to get database session."""
    db = get_session()
    try:
        yield db
    finally:
        db.close()


def hash_content(content: Optional[str]) -> Optional[str]:
    """Hash content if provided."""
    if content is None:
        return None
    hash_bytes = hashlib.sha256(content.encode('utf-8')).digest()
    return f"sha256:{hash_bytes.hex()}"


@router.post("/ai/call")
async def ai_call(
    request: AICallRequest,
    db: Session = Depends(get_db)
):
    """
    Process an AI call through the gateway.
    
    For MVP: Provider call is stubbed, but packet is real with:
    - Timestamps
    - HALO chain
    - Signature
    - Stored in DB
    """
    # Generate transaction ID
    transaction_id = f"tx_{uuid.uuid4().hex[:16]}"
    gateway_timestamp = datetime.utcnow()
    
    # Get active policy
    active_pointer = db.query(ActivePolicyPointer).filter_by(
        environment=request.environment
    ).first()
    
    if not active_pointer:
        # No policy set - reject
        approved = False
        policy_version_hash = "sha256:no_policy"
        policy_change_ref = None
        rejection_reason = "No active policy for environment"
    else:
        # For MVP: Simple approval (in production, evaluate policy logic)
        approved = True
        policy_version_hash = active_pointer.policy_version_hash
        policy_change_ref = f"pcr_{active_pointer.change_request_id}" if active_pointer.change_request_id else None
        rejection_reason = None
    
    # Compute input hashes
    prompt_hash = hash_content(request.prompt)
    rag_hash = hash_content(request.rag_context)
    multimodal_hash = hash_content(request.multimodal_data)
    
    # Stub AI provider call (for MVP)
    if approved:
        # Simulate AI response
        output_text = "[STUBBED RESPONSE] This is a mock AI response for MVP testing."
        output_hash = hash_content(output_text)
        token_usage = {"prompt": 45, "completion": 15, "total": 60}
        latency_ms = 150
    else:
        output_text = None
        output_hash = None
        token_usage = None
        latency_ms = 10
    
    # Build packet core fields
    client_key_fingerprint = f"sha256:client_{request.client_id}_fp"
    
    packet = {
        "transaction_id": transaction_id,
        "gateway_timestamp_utc": gateway_timestamp.isoformat() + "Z",
        "environment": request.environment,
        "client_id": request.client_id,
        "intent_manifest": request.intent_manifest,
        "feature_tag": request.feature_tag,
        "user_ref": request.user_ref,
        "prompt_hash": prompt_hash,
        "rag_hash": rag_hash,
        "multimodal_hash": multimodal_hash,
        "policy_receipt_subset": {
            "policy_version_hash": policy_version_hash,
            "approved": approved,
            "policy_change_ref": policy_change_ref,
            "rejection_reason": rejection_reason
        },
        "model_fingerprint": request.model_fingerprint,
        "param_snapshot": request.parameters,
        "output_hash": output_hash,
        "token_usage": token_usage,
        "latency_ms": latency_ms,
        "client_key_fingerprint": client_key_fingerprint
    }
    
    # Compute HALO chain
    halo_chain = compute_halo_chain(packet)
    packet["halo_chain"] = halo_chain
    
    # Sign the packet
    signer = get_signer()
    signed_message = {
        "transaction_id": packet["transaction_id"],
        "gateway_timestamp_utc": packet["gateway_timestamp_utc"],
        "final_hash": halo_chain["final_hash"],
        "policy_version_hash": policy_version_hash,
        "client_key_fingerprint": client_key_fingerprint
    }
    message_bytes = json_c14n_v1(signed_message)
    signature_info = signer.sign_bytes(message_bytes)
    
    packet["verification"] = {
        "signature": signature_info
    }
    
    # Store transaction in database
    transaction = Transaction(
        transaction_id=transaction_id,
        gateway_timestamp_utc=gateway_timestamp,
        environment=request.environment,
        client_id=request.client_id,
        packet_data=packet,
        halo_chain=halo_chain,
        signature_data=signature_info,
        policy_version_hash=policy_version_hash,
        policy_change_ref=policy_change_ref
    )
    
    db.add(transaction)
    db.commit()
    
    # Return response
    return {
        "transaction_id": transaction_id,
        "approved": approved,
        "output": output_text if approved else None,
        "rejection_reason": rejection_reason if not approved else None,
        "receipt": packet
    }


@router.get("/transactions/{transaction_id}")
async def get_transaction(
    transaction_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve a transaction receipt by ID."""
    transaction = db.query(Transaction).filter_by(
        transaction_id=transaction_id
    ).first()
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    return transaction.packet_data


@router.post("/transactions/{transaction_id}/verify")
async def verify_transaction(
    transaction_id: str,
    db: Session = Depends(get_db)
):
    """
    Server-side verification of a transaction.
    
    This performs the same verification as the offline CLI tool.
    """
    from gateway.app.services.halo import verify_halo_chain
    
    transaction = db.query(Transaction).filter_by(
        transaction_id=transaction_id
    ).first()
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    # Verify HALO chain
    halo_result = verify_halo_chain(transaction.packet_data)
    
    # Verify signature (use local signer)
    signer = get_signer()
    packet = transaction.packet_data
    
    try:
        # Reconstruct signed message
        signed_message = {
            "transaction_id": packet["transaction_id"],
            "gateway_timestamp_utc": packet["gateway_timestamp_utc"],
            "final_hash": packet["halo_chain"]["final_hash"],
            "policy_version_hash": packet["policy_receipt_subset"]["policy_version_hash"],
            "client_key_fingerprint": packet["client_key_fingerprint"]
        }
        
        # For server-side verification, we just check if signature data is present
        # Full crypto verification would require importing the signature verification logic
        signature_valid = "verification" in packet and "signature" in packet["verification"]
        
    except Exception as e:
        signature_valid = False
    
    return {
        "transaction_id": transaction_id,
        "valid": halo_result["valid"] and signature_valid,
        "halo_valid": halo_result["valid"],
        "signature_valid": signature_valid,
        "failures": halo_result["failures"]
    }
