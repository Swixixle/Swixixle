"""
HALO hash chain implementation (halo_v1)

HALO (Hash-Anchored Layered Operands) provides tamper-evident chaining of transaction data.

Block structure:
- block_1: Core transaction identifiers
- block_2: Intent and context
- block_3: Input hashes  
- block_4: Policy and model metadata
- final_hash: Output and metrics
"""

import hashlib
from typing import Any, Dict, Optional
from gateway.app.services.c14n import json_c14n_v1


def compute_halo_chain(packet_core_fields: Dict[str, Any]) -> Dict[str, str]:
    """
    Compute HALO hash chain for a transaction packet.
    
    Args:
        packet_core_fields: Dictionary containing all required fields for HALO blocks
        
    Returns:
        Dictionary with block_1, block_2, block_3, block_4, and final_hash
        
    Block definitions:
    - block_1: {transaction_id, gateway_timestamp_utc, environment, client_id}
    - block_2: {intent_manifest, feature_tag, user_ref}
    - block_3: {prompt_hash, rag_hash, multimodal_hash}
    - block_4: {policy_receipt_subset, model_fingerprint, param_snapshot}
    - final: {output_hash, token_usage, latency_ms}
    
    Each block hash includes the previous block's hash, creating a chain.
    """
    
    # Block 1: Core transaction identifiers
    block_1_data = {
        "transaction_id": packet_core_fields.get("transaction_id"),
        "gateway_timestamp_utc": packet_core_fields.get("gateway_timestamp_utc"),
        "environment": packet_core_fields.get("environment"),
        "client_id": packet_core_fields.get("client_id")
    }
    block_1_hash = _hash_block(block_1_data)
    
    # Block 2: Intent and context (includes previous block)
    block_2_data = {
        "previous_hash": block_1_hash,
        "intent_manifest": packet_core_fields.get("intent_manifest"),
        "feature_tag": packet_core_fields.get("feature_tag"),
        "user_ref": packet_core_fields.get("user_ref")
    }
    block_2_hash = _hash_block(block_2_data)
    
    # Block 3: Input hashes (includes previous block)
    block_3_data = {
        "previous_hash": block_2_hash,
        "prompt_hash": packet_core_fields.get("prompt_hash"),
        "rag_hash": packet_core_fields.get("rag_hash"),
        "multimodal_hash": packet_core_fields.get("multimodal_hash")
    }
    block_3_hash = _hash_block(block_3_data)
    
    # Block 4: Policy and model metadata (includes previous block)
    block_4_data = {
        "previous_hash": block_3_hash,
        "policy_receipt_subset": packet_core_fields.get("policy_receipt_subset"),
        "model_fingerprint": packet_core_fields.get("model_fingerprint"),
        "param_snapshot": packet_core_fields.get("param_snapshot")
    }
    block_4_hash = _hash_block(block_4_data)
    
    # Final hash: Output and metrics (includes previous block)
    # Note: output_hash can be null if request was denied, but still include in final
    final_data = {
        "previous_hash": block_4_hash,
        "output_hash": packet_core_fields.get("output_hash"),
        "token_usage": packet_core_fields.get("token_usage"),
        "latency_ms": packet_core_fields.get("latency_ms")
    }
    final_hash = _hash_block(final_data)
    
    return {
        "block_1": block_1_hash,
        "block_2": block_2_hash,
        "block_3": block_3_hash,
        "block_4": block_4_hash,
        "final_hash": final_hash
    }


def verify_halo_chain(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify the HALO hash chain in a transaction packet.
    
    Args:
        packet: Complete transaction packet with HALO chain
        
    Returns:
        Verification report with:
        - valid: bool
        - failures: list of failure descriptions
        - verified_blocks: list of successfully verified blocks
    """
    failures = []
    verified_blocks = []
    
    try:
        # Extract HALO chain from packet
        halo_chain = packet.get("halo_chain", {})
        if not halo_chain:
            return {
                "valid": False,
                "failures": ["Missing halo_chain in packet"],
                "verified_blocks": []
            }
        
        # Recompute the chain
        computed_chain = compute_halo_chain(packet)
        
        # Verify each block
        for block_name in ["block_1", "block_2", "block_3", "block_4", "final_hash"]:
            expected = computed_chain.get(block_name)
            actual = halo_chain.get(block_name)
            
            if expected != actual:
                failures.append(
                    f"{block_name} mismatch: expected {expected}, got {actual}"
                )
            else:
                verified_blocks.append(block_name)
        
        return {
            "valid": len(failures) == 0,
            "failures": failures,
            "verified_blocks": verified_blocks
        }
        
    except Exception as e:
        return {
            "valid": False,
            "failures": [f"Verification error: {str(e)}"],
            "verified_blocks": verified_blocks
        }


def _hash_block(block_data: Dict[str, Any]) -> str:
    """
    Hash a block using canonical JSON and SHA256.
    
    Args:
        block_data: Block data to hash
        
    Returns:
        SHA256 hash in format "sha256:<hex>"
    """
    canonical_bytes = json_c14n_v1(block_data)
    hash_bytes = hashlib.sha256(canonical_bytes).digest()
    hash_hex = hash_bytes.hex()
    return f"sha256:{hash_hex}"
