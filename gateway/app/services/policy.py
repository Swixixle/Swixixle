"""
Policy service for policy governance and hashing

Policies are content-addressed by their logic (excluding metadata).
"""

import hashlib
from typing import Dict, Any
from gateway.app.services.c14n import json_c14n_v1


def compute_policy_hash(policy_logic: Dict[str, Any]) -> str:
    """
    Compute content-addressed hash of policy logic.
    
    Args:
        policy_logic: Policy logic dictionary (without timestamps/metadata)
        
    Returns:
        Policy hash in format "sha256:<hex>"
    """
    canonical_bytes = json_c14n_v1(policy_logic)
    hash_bytes = hashlib.sha256(canonical_bytes).digest()
    hash_hex = hash_bytes.hex()
    return f"sha256:{hash_hex}"


def validate_policy_logic(policy_logic: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate policy logic structure.
    
    Args:
        policy_logic: Policy logic to validate
        
    Returns:
        Validation result with valid (bool) and errors (list)
    """
    errors = []
    
    # Required fields
    if "rules" not in policy_logic:
        errors.append("Missing 'rules' field")
    
    if "version" not in policy_logic:
        errors.append("Missing 'version' field")
    
    # Validate rules structure
    if "rules" in policy_logic:
        rules = policy_logic["rules"]
        if not isinstance(rules, list):
            errors.append("'rules' must be a list")
        else:
            for i, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    errors.append(f"Rule {i} must be a dictionary")
                elif "condition" not in rule or "action" not in rule:
                    errors.append(f"Rule {i} must have 'condition' and 'action'")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }
