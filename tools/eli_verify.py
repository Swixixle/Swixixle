#!/usr/bin/env python3
"""
eli_verify.py - Offline verifier CLI for ELI-Sentinel transaction receipts

This is a standalone, portable verification tool that:
1. Verifies HALO hash chain integrity
2. Verifies cryptographic signature
3. Provides both human and machine-readable output

Exit codes:
  0 - Valid transaction
  2 - HALO chain verification failed
  3 - Signature verification failed
  4 - Key fetch failed
  10 - Schema validation failed
"""

import sys
import json
import hashlib
import argparse
import base64
from typing import Any, Dict, List, Optional
from pathlib import Path


# ============================================================================
# CANONICAL JSON (embedded for portability)
# ============================================================================

def json_c14n_v1(obj: Any) -> bytes:
    """Canonicalize a Python object to deterministic JSON bytes."""
    import math
    
    def validate_no_special_floats(obj: Any) -> None:
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                raise ValueError("NaN and Infinity are not allowed")
        elif isinstance(obj, dict):
            for value in obj.values():
                validate_no_special_floats(value)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                validate_no_special_floats(item)
    
    validate_no_special_floats(obj)
    canonical_str = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
        allow_nan=False
    )
    return canonical_str.encode('utf-8')


# ============================================================================
# HALO CHAIN VERIFICATION (embedded for portability)
# ============================================================================

def hash_block(block_data: Dict[str, Any]) -> str:
    """Hash a block using canonical JSON and SHA256."""
    canonical_bytes = json_c14n_v1(block_data)
    hash_bytes = hashlib.sha256(canonical_bytes).digest()
    hash_hex = hash_bytes.hex()
    return f"sha256:{hash_hex}"


def compute_halo_chain(packet: Dict[str, Any]) -> Dict[str, str]:
    """Compute HALO hash chain for a transaction packet."""
    # Block 1: Core transaction identifiers
    block_1_data = {
        "transaction_id": packet.get("transaction_id"),
        "gateway_timestamp_utc": packet.get("gateway_timestamp_utc"),
        "environment": packet.get("environment"),
        "client_id": packet.get("client_id")
    }
    block_1_hash = hash_block(block_1_data)
    
    # Block 2: Intent and context
    block_2_data = {
        "previous_hash": block_1_hash,
        "intent_manifest": packet.get("intent_manifest"),
        "feature_tag": packet.get("feature_tag"),
        "user_ref": packet.get("user_ref")
    }
    block_2_hash = hash_block(block_2_data)
    
    # Block 3: Input hashes
    block_3_data = {
        "previous_hash": block_2_hash,
        "prompt_hash": packet.get("prompt_hash"),
        "rag_hash": packet.get("rag_hash"),
        "multimodal_hash": packet.get("multimodal_hash")
    }
    block_3_hash = hash_block(block_3_data)
    
    # Block 4: Policy and model metadata
    block_4_data = {
        "previous_hash": block_3_hash,
        "policy_receipt_subset": packet.get("policy_receipt_subset"),
        "model_fingerprint": packet.get("model_fingerprint"),
        "param_snapshot": packet.get("param_snapshot")
    }
    block_4_hash = hash_block(block_4_data)
    
    # Final hash: Output and metrics
    final_data = {
        "previous_hash": block_4_hash,
        "output_hash": packet.get("output_hash"),
        "token_usage": packet.get("token_usage"),
        "latency_ms": packet.get("latency_ms")
    }
    final_hash = hash_block(final_data)
    
    return {
        "block_1": block_1_hash,
        "block_2": block_2_hash,
        "block_3": block_3_hash,
        "block_4": block_4_hash,
        "final_hash": final_hash
    }


def verify_halo_chain(packet: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the HALO hash chain in a transaction packet."""
    failures = []
    verified_blocks = []
    
    try:
        halo_chain = packet.get("halo_chain", {})
        if not halo_chain:
            return {
                "valid": False,
                "failures": ["Missing halo_chain in packet"],
                "verified_blocks": []
            }
        
        computed_chain = compute_halo_chain(packet)
        
        for block_name in ["block_1", "block_2", "block_3", "block_4", "final_hash"]:
            expected = computed_chain.get(block_name)
            actual = halo_chain.get(block_name)
            
            if expected != actual:
                failures.append(f"{block_name} mismatch")
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


# ============================================================================
# SIGNATURE VERIFICATION
# ============================================================================

def load_jwk_from_file(jwk_path: str) -> Dict[str, Any]:
    """Load JWK from a file."""
    try:
        with open(jwk_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        raise Exception(f"JWK file not found: {jwk_path}")
    except json.JSONDecodeError:
        raise Exception(f"Invalid JSON in JWK file: {jwk_path}")


def fetch_jwk_from_url(keys_url: str, key_id: str) -> Dict[str, Any]:
    """Fetch JWK from a keys endpoint."""
    try:
        import urllib.request
        import urllib.error
        
        # Construct URL for specific key
        url = f"{keys_url.rstrip('/')}/{key_id}"
        
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read())
            
    except urllib.error.URLError as e:
        raise Exception(f"Failed to fetch key from {url}: {str(e)}")
    except json.JSONDecodeError:
        raise Exception(f"Invalid JSON response from {url}")


def verify_signature(packet: Dict[str, Any], jwk: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify the cryptographic signature on a packet.
    
    The signed message is canonical JSON of:
    {
        "transaction_id": "...",
        "gateway_timestamp_utc": "...",
        "final_hash": "sha256:...",
        "policy_version_hash": "sha256:...",
        "client_key_fingerprint": "sha256:..."
    }
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        
        # Extract signature from packet
        verification = packet.get("verification", {})
        signature_info = verification.get("signature", {})
        
        if not signature_info:
            return {"valid": False, "error": "Missing signature in packet"}
        
        signature_b64 = signature_info.get("signature_b64")
        if not signature_b64:
            return {"valid": False, "error": "Missing signature_b64"}
        
        # Decode signature
        signature_bytes = base64.b64decode(signature_b64)
        
        # Reconstruct the signed message
        halo_chain = packet.get("halo_chain", {})
        policy_receipt = packet.get("policy_receipt_subset", {})
        
        signed_message = {
            "transaction_id": packet.get("transaction_id"),
            "gateway_timestamp_utc": packet.get("gateway_timestamp_utc"),
            "final_hash": halo_chain.get("final_hash"),
            "policy_version_hash": policy_receipt.get("policy_version_hash"),
            "client_key_fingerprint": packet.get("client_key_fingerprint")
        }
        
        message_bytes = json_c14n_v1(signed_message)
        
        # Load public key from JWK
        if jwk.get("kty") != "RSA":
            return {"valid": False, "error": f"Unsupported key type: {jwk.get('kty')}"}
        
        # Helper to add correct base64url padding
        def add_padding(b64url_str):
            return b64url_str + "=" * (4 - len(b64url_str) % 4)
        
        # Convert JWK to public key
        n = int.from_bytes(base64.urlsafe_b64decode(add_padding(jwk["n"])), byteorder='big')
        e = int.from_bytes(base64.urlsafe_b64decode(add_padding(jwk["e"])), byteorder='big')
        
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())
        
        # Verify signature
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return {"valid": True}
        
    except Exception as e:
        return {"valid": False, "error": f"Signature verification failed: {str(e)}"}


# ============================================================================
# SCHEMA VALIDATION
# ============================================================================

def validate_packet_schema(packet: Dict[str, Any]) -> Dict[str, Any]:
    """Validate that packet has required fields."""
    failures = []
    
    required_fields = [
        "transaction_id",
        "gateway_timestamp_utc",
        "environment",
        "client_id",
        "halo_chain"
    ]
    
    for field in required_fields:
        if field not in packet:
            failures.append(f"Missing required field: {field}")
    
    # Validate halo_chain structure
    if "halo_chain" in packet:
        halo_chain = packet["halo_chain"]
        required_blocks = ["block_1", "block_2", "block_3", "block_4", "final_hash"]
        for block in required_blocks:
            if block not in halo_chain:
                failures.append(f"Missing HALO block: {block}")
    
    return {
        "valid": len(failures) == 0,
        "failures": failures
    }


# ============================================================================
# MAIN VERIFICATION LOGIC
# ============================================================================

def verify_packet(
    packet: Dict[str, Any],
    jwk: Optional[Dict[str, Any]] = None,
    skip_signature: bool = False
) -> Dict[str, Any]:
    """
    Main verification function.
    
    Returns:
        Dictionary with verification results:
        - valid: bool
        - schema_valid: bool
        - halo_valid: bool
        - signature_valid: bool (if checked)
        - failures: list of errors
    """
    result = {
        "valid": True,
        "failures": []
    }
    
    # Step 1: Schema validation
    schema_result = validate_packet_schema(packet)
    result["schema_valid"] = schema_result["valid"]
    if not schema_result["valid"]:
        result["valid"] = False
        result["failures"].extend(schema_result["failures"])
        return result  # Can't continue without valid schema
    
    # Step 2: HALO chain verification
    halo_result = verify_halo_chain(packet)
    result["halo_valid"] = halo_result["valid"]
    if not halo_result["valid"]:
        result["valid"] = False
        result["failures"].extend([f"HALO: {f}" for f in halo_result["failures"]])
    
    # Step 3: Signature verification (if not skipped)
    if not skip_signature:
        if jwk is None:
            result["signature_valid"] = False
            result["valid"] = False
            result["failures"].append("No JWK provided for signature verification")
        else:
            sig_result = verify_signature(packet, jwk)
            result["signature_valid"] = sig_result["valid"]
            if not sig_result["valid"]:
                result["valid"] = False
                result["failures"].append(f"Signature: {sig_result.get('error', 'verification failed')}")
    
    return result


# ============================================================================
# CLI INTERFACE
# ============================================================================

def print_human_summary(packet: Dict[str, Any], result: Dict[str, Any]):
    """Print human-readable verification summary."""
    print("\n" + "=" * 70)
    print("ELI-SENTINEL TRANSACTION RECEIPT VERIFICATION")
    print("=" * 70)
    
    # Transaction info
    print(f"\nTransaction ID: {packet.get('transaction_id', 'N/A')}")
    print(f"Timestamp: {packet.get('gateway_timestamp_utc', 'N/A')}")
    print(f"Environment: {packet.get('environment', 'N/A')}")
    print(f"Client ID: {packet.get('client_id', 'N/A')}")
    
    # Verification results
    print("\n" + "-" * 70)
    print("VERIFICATION RESULTS:")
    print("-" * 70)
    
    def status_icon(valid):
        return "✓" if valid else "✗"
    
    print(f"{status_icon(result.get('schema_valid', False))} Schema validation")
    print(f"{status_icon(result.get('halo_valid', False))} HALO chain integrity")
    
    if "signature_valid" in result:
        print(f"{status_icon(result['signature_valid'])} Cryptographic signature")
    
    print("\n" + "-" * 70)
    
    if result["valid"]:
        print("✓ VALID - Transaction receipt verified successfully")
    else:
        print("✗ INVALID - Verification failed")
        print("\nFailures:")
        for failure in result["failures"]:
            print(f"  • {failure}")
    
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Verify ELI-Sentinel transaction receipts offline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  - Transaction verified successfully
  2  - HALO chain verification failed
  3  - Signature verification failed
  4  - Key fetch failed
  10 - Schema validation failed

Examples:
  # Verify with local JWK file
  ./eli_verify.py packet.json --jwk key.jwk
  
  # Verify with keys endpoint
  ./eli_verify.py packet.json --keys-url https://api.example.com/v1/keys
  
  # Machine-readable output
  ./eli_verify.py packet.json --jwk key.jwk --json
        """
    )
    
    parser.add_argument("packet_file", help="Path to transaction packet JSON file")
    parser.add_argument("--jwk", help="Path to JWK file for signature verification")
    parser.add_argument("--keys-url", help="URL to keys endpoint for fetching JWK")
    parser.add_argument("--skip-signature", action="store_true", 
                       help="Skip signature verification (only verify HALO chain)")
    parser.add_argument("--json", action="store_true",
                       help="Output results as JSON instead of human-readable")
    
    args = parser.parse_args()
    
    # Load packet
    try:
        with open(args.packet_file, 'r') as f:
            packet = json.load(f)
    except FileNotFoundError:
        print(f"Error: Packet file not found: {args.packet_file}", file=sys.stderr)
        sys.exit(10)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in packet file: {e}", file=sys.stderr)
        sys.exit(10)
    
    # Load JWK if signature verification requested
    jwk = None
    if not args.skip_signature:
        if args.jwk:
            try:
                jwk = load_jwk_from_file(args.jwk)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(4)
        elif args.keys_url:
            # Extract key_id from packet
            verification = packet.get("verification", {})
            signature_info = verification.get("signature", {})
            key_id = signature_info.get("key_id")
            
            if not key_id:
                print("Error: No key_id found in packet signature", file=sys.stderr)
                sys.exit(4)
            
            try:
                jwk = fetch_jwk_from_url(args.keys_url, key_id)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(4)
        else:
            print("Error: Must provide either --jwk or --keys-url for signature verification", 
                  file=sys.stderr)
            print("       (or use --skip-signature to skip signature verification)", 
                  file=sys.stderr)
            sys.exit(4)
    
    # Verify packet
    result = verify_packet(packet, jwk, skip_signature=args.skip_signature)
    
    # Output results
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human_summary(packet, result)
    
    # Exit with appropriate code
    if result["valid"]:
        sys.exit(0)
    elif not result.get("schema_valid", True):
        sys.exit(10)
    elif not result.get("halo_valid", True):
        sys.exit(2)
    elif not result.get("signature_valid", True):
        sys.exit(3)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
